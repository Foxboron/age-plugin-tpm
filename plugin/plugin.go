package plugin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	PluginName      = "tpm"
	BinaryName      = "age-plugin-yubikey"
	RecipientPrefix = "age1tpm"
	IdentityPrefix  = "age-plugin-tpm-"
)

// Creates a Storage Key, or return the loaded storage key
func CreateSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}, srkPublic, nil
}

func CreateIdentity(tpm transport.TPMCloser, pin []byte) (*Identity, *Recipient, error) {
	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer FlushHandle(tpm, srkHandle)

	eccKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDH,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDH,
							&tpm2.TPMSKeySchemeECDH{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	pinstatus := NoPIN

	if !bytes.Equal(pin, []byte("")) {
		eccKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: pin,
				},
			},
		}
		pinstatus = HasPIN
	}

	var eccRsp *tpm2.CreateResponse
	eccRsp, err = eccKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	identity := &Identity{
		Version: 1,
		PIN:     pinstatus,
		Private: eccRsp.OutPrivate,
		Public:  eccRsp.OutPublic,
	}

	recipient, err := identity.Recipient()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting recipient: %v", err)
	}
	return identity, recipient, nil
}

func LoadIdentity(tpm transport.TPMCloser, identity *Identity) (*tpm2.AuthHandle, error) {
	srkHandle, _, err := CreateSRK(tpm)
	if err != nil {
		return nil, err
	}

	defer FlushHandle(tpm, srkHandle)

	return LoadIdentityWithParent(tpm, *srkHandle, identity)
}

func LoadIdentityWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, identity *Identity) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    identity.Private,
		InPublic:     identity.Public,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func DecryptTPM(tpm transport.TPMCloser, identity *Identity, remoteKey, fileKey, pin []byte) ([]byte, error) {
	x, y, sessionKey, err := UnmarshalCompressedECDH(remoteKey)
	if err != nil {
		return nil, err
	}

	swPub := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	handle, err := LoadIdentity(tpm, identity)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpm, handle.Handle)

	// Add the AuthSession for the handle
	handle.Auth = tpm2.PasswordAuth(pin)

	ecdh := tpm2.ECDHZGen{
		KeyHandle: handle,
		InPoint:   tpm2.New2B(swPub),
	}

	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting srk: %v", err)
	}

	defer FlushHandle(tpm, srkHandle)

	ecdhRsp, err := ecdh.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed ecdhzgen: %v", err)
	}

	sharedSecret, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed getting ecdh point: %v", err)
	}

	resp, err := identity.Recipient()
	if err != nil {
		return nil, err
	}

	ourKey := resp.Pubkey.Bytes()

	theirKey := sessionKey.Bytes()

	salt := make([]byte, 0, len(theirKey)+len(ourKey))
	salt = append(salt, theirKey...)
	salt = append(salt, ourKey...)

	h := hkdf.New(sha256.New, sharedSecret.X.Buffer, salt, []byte(p256Label))
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
