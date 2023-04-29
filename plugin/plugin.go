package plugin

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	PluginName      = "tpm"
	BinaryName      = "age-plugin-yubikey"
	RecipientPrefix = "age1tpm"
	IdentityPrefix  = "age-plugin-tpm-"
)

// TPM Variables
var (
	// Default SRK handle
	srkHandle tpmutil.Handle = 0x81000001

	// Default SRK handle
	localHandle tpmutil.Handle = 0x81000004

	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	eccKeyParamsDecrypt = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault & ^tpm2.FlagRestricted,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}
)

func CreateIdentity(tpm io.ReadWriteCloser) (*Identity, error) {
	if !HasKey(tpm, srkHandle) {
		handle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed CreatePrimary: %v", err)
		}
		if err = tpm2.EvictControl(tpm, "", tpm2.HandleOwner, handle, srkHandle); err != nil {
			return nil, fmt.Errorf("failed EvictControl of srk: %v", err)
		}
	}

	priv, pub, _, _, _, err := tpm2.CreateKey(tpm, srkHandle, tpm2.PCRSelection{}, "", "", eccKeyParamsDecrypt)
	if err != nil {
		return nil, fmt.Errorf("failed CreateKey: %v", err)
	}
	sealedHandle, _, err := tpm2.Load(tpm, srkHandle, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("failed Load: %v", err)
	}
	defer tpm2.FlushContext(tpm, sealedHandle)
	if err = tpm2.EvictControl(tpm, "", tpm2.HandleOwner, sealedHandle, localHandle); err != nil {
		return nil, fmt.Errorf("failed EvictControl: %v", err)
	}

	pk := GetPubKey(tpm, localHandle)
	s, err := EncodeRecipient(localHandle, pk)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Version:   1,
		Handle:    localHandle,
		PIN:       HasPIN,
		Created:   time.Now(),
		Recipient: s,
	}, nil
}

func HasKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) bool {
	if _, _, _, err := tpm2.ReadPublic(tpm, handle); err != nil {
		return false
	}
	return true
}

func GetPubKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) *ecdh.PublicKey {
	pub, _, _, err := tpm2.ReadPublic(tpm, handle)
	if err != nil {
		log.Fatal(err)
	}
	pubkey, _ := pub.Key()
	ecKey, err := pubkey.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		log.Fatalf("failed creating ECDH key from tpm: %v", err)
	}

	return ecKey
}

func GetTPM(tpm io.ReadWriteCloser) {
	tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.FirmwareVersion1))
}

func DecryptTPM(tpm io.ReadWriteCloser, handle tpmutil.Handle, remoteKey []byte, fileKey []byte) ([]byte, error) {

	x, y, sessionKey, err := UnmarshalCompressedECDH(remoteKey)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := tpm2.ECDHZGen(tpm, handle, "",
		tpm2.ECPoint{XRaw: x.Bytes(), YRaw: y.Bytes()})
	if err != nil {
		return nil, err
	}

	ourKey := GetPubKey(tpm, handle).Bytes()
	theirKey := sessionKey.Bytes()

	salt := make([]byte, 0, len(theirKey)+len(ourKey))
	salt = append(salt, theirKey...)
	salt = append(salt, ourKey...)

	h := hkdf.New(sha256.New, sharedSecret.X().Bytes(), salt, []byte(p256Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)

	decrypted, err := aead.Open(nil, nonce, fileKey, nil)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return []byte{}, err
	}

	return decrypted, nil
}

func DeleteHandle(tpm io.ReadWriteCloser, handle tpmutil.Handle) error {
	if err := tpm2.EvictControl(tpm, "", tpm2.HandleOwner, handle, handle); err != nil {
		return fmt.Errorf("failed EvictControl: %v", err)
	}
	return nil
}

func HandleToString(handle tpmutil.Handle) string {
	return fmt.Sprintf("0x%x", handle)
}

func StringToHandle(handle string) (tpmutil.Handle, error) {
	if !strings.HasPrefix(handle, "0x") {
		return 0, fmt.Errorf("handle should be formatted as a hex-string with an 0x prefix")
	}
	hex := strings.TrimPrefix(handle, "0x")
	value, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		return 0, err
	}
	return tpmutil.Handle(value), nil
}

// Unmarshal a compressed ec key
func UnmarshalCompressedECDH(b []byte) (*big.Int, *big.Int, *ecdh.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	ec := ecdsa.PublicKey{
		Curve: elliptic.P256(), X: x, Y: y,
	}
	key, err := ec.ECDH()
	return x, y, key, err
}

// Marshal a compressed EC key
func MarshalCompressedECDH(pk *ecdh.PublicKey) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), pk.Bytes())
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}
