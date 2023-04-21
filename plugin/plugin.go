package plugin

import (
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	rsaKeyParamsDecrypt = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func CreateKey(tpm io.ReadWriteCloser) (*Key, error) {
	if !HasKey(tpm, srkHandle) {
		handle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed CreatePrimary: %v", err)
		}
		if err = tpm2.EvictControl(tpm, "", tpm2.HandleOwner, handle, srkHandle); err != nil {
			return nil, fmt.Errorf("failed EvictControl of srk: %v", err)
		}
	}

	priv, pub, _, _, _, err := tpm2.CreateKey(tpm, srkHandle, tpm2.PCRSelection{}, "", "", rsaKeyParamsDecrypt)
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
	return &Key{
		Version:   1,
		Handle:    localHandle,
		PIN:       HasPIN,
		Created:   time.Now(),
		Recipient: s,
	}, nil
}

func PrintKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) error {
	pub, _, _, err := tpm2.ReadPublic(tpm, localHandle)
	if err != nil {
		return fmt.Errorf("failed to ReadPublic: %v", err)
	}
	pubkey, err := pub.Key()
	if err != nil {
		return fmt.Errorf("failed getting key: %v", err)
	}

	rsaPubKey := pubkey.(*rsa.PublicKey)

	fmt.Println(KeyToSSH(rsaPubKey))
	return nil
}

func HasKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) bool {
	if _, _, _, err := tpm2.ReadPublic(tpm, handle); err != nil {
		return false
	}
	return true
}

func GetPubKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) *rsa.PublicKey {
	pub, _, _, err := tpm2.ReadPublic(tpm, handle)
	if err != nil {
		log.Fatal(err)
	}
	pubkey, _ := pub.Key()

	return pubkey.(*rsa.PublicKey)
}

func GetTPM(tpm io.ReadWriteCloser) {
	tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.FirmwareVersion1))
}

func DecryptTPM(tpm io.ReadWriteCloser, handle tpmutil.Handle, fileKey []byte) ([]byte, error) {
	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	fileKey, err := tpm2.RSADecrypt(tpm, handle, "", fileKey, scheme, oaepTPMLabel)
	if err != nil {
		return []byte{}, err
	}

	return fileKey, nil
}

func DeleteHandle(tpm io.ReadWriteCloser, handle tpmutil.Handle) error {
	if err := tpm2.EvictControl(tpm, "", tpm2.HandleOwner, handle, handle); err != nil {
		return fmt.Errorf("failed EvictControl: %v", err)
	}
	return nil
}
