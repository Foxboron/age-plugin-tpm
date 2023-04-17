package plugin

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/foxboron/age-plugin-tpm/internal/format"
	"github.com/foxboron/age-plugin-tpm/internal/stream"
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
	StanzaTag       = "idk"
)

// TPM Variables
var (
	// Default SRK handle
	srkHandle tpmutil.Handle = 0x81000001

	// Default SRK handle
	localHandle tpmutil.Handle = 0x81000004

	oaepLabel = "age-encryption.org/v1/ssh-rsa"

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

func policySession(tpm io.ReadWriteCloser, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	sessHandle, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	// defer func() {
	// 	if sessHandle != tpm2.HandleNull && err != nil {
	// 		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
	// 			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
	// 		}
	// 	}
	// }()

	// pcrSelection := tpm2.PCRSelection{
	// 	Hash: tpm2.AlgSHA256,
	// 	PCRs: []int{pcr},
	// }

	// An empty expected digest means that digest verification is skipped.
	// if err := tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
	// 	return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	// }

	if password != "" {
		if err := tpm2.PolicyPassword(tpm, sessHandle); err != nil {
			return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
		}
	}

	policy, err = tpm2.PolicyGetDigest(tpm, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

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

	pk := GetKey(tpm, localHandle)
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

func GetKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) *rsa.PublicKey {
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

// Some copypasta from age/internal
const (
	fileKeySize     = 16
	streamNonceSize = 16
)

type Stanza struct {
	Type string
	Args []string
	Body []byte
}

func streamKey(fileKey, nonce []byte) []byte {
	h := hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		panic("age: internal error: failed to read from HKDF: " + err.Error())
	}
	return streamKey
}

func Decrypt(tpm io.ReadWriteCloser, handle tpmutil.Handle, file string) error {
	var r io.Reader
	var err error
	r, err = os.Open(file)
	if err != nil {
		return err
	}
	hdr, payload, err := format.Parse(r)
	if err != nil {
		log.Fatal(err)
	}

	stanzas := make([]*Stanza, 0, len(hdr.Recipients))
	for _, s := range hdr.Recipients {
		stanzas = append(stanzas, (*Stanza)(s))
	}

	pb := stanzas[0]

	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	fileKey, err := tpm2.RSADecrypt(tpm, handle, "test", pb.Body, scheme, oaepLabel)
	if err != nil {
		return err
	}

	nonce := make([]byte, streamNonceSize)
	if _, err := io.ReadFull(payload, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	sReader, err := stream.NewReader(streamKey(fileKey, nonce), payload)
	if err != nil {
		log.Fatal(err)
	}

	bb := bytes.NewBuffer([]byte{})
	if _, err := io.Copy(bb, sReader); err != nil {
		return err
	}
	fmt.Println(bb.String())
	return nil
}

func Encrypt(tpm io.ReadWriteCloser, handle tpmutil.Handle) error {
	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	b, err := tpm2.RSAEncrypt(tpm, handle, []byte("test"), scheme, oaepLabel)
	if err != nil {
		return err
	}
	b, err = tpm2.RSADecrypt(tpm, handle, "test", b, scheme, oaepLabel)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func DecryptTPM(tpm io.ReadWriteCloser, handle tpmutil.Handle, fileKey []byte) ([]byte, error) {
	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	fileKey, err := tpm2.RSADecrypt(tpm, handle, "", fileKey, scheme, oaepTPMLabel)
	if err != nil {
		return []byte{}, err
	}

	return fileKey, nil
}

func DeleteKey(tpm io.ReadWriteCloser, handle tpmutil.Handle) error {
	if err := tpm2.EvictControl(tpm, "", tpm2.HandleOwner, handle, handle); err != nil {
		return fmt.Errorf("failed EvictControl: %v", err)
	}
	return nil
}
