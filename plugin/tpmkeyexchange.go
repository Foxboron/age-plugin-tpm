package plugin

import (
	"crypto/elliptic"
	"fmt"

	"filippo.io/hpke/crypto/ecdh"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMKeyExchange struct {
	tpm transport.TPMCloser
	i   *Identity
	pin []byte
}

var _ ecdh.KeyExchanger = &TPMKeyExchange{}

func (t *TPMKeyExchange) PublicKey() *ecdh.PublicKey {
	return t.i.Publickey()
}

func (t *TPMKeyExchange) Curve() ecdh.Curve {
	// TODO: We can derive this from the TPM key. But this is never going to change.
	return ecdh.P256()
}

func (t *TPMKeyExchange) ECDH(remoteKey *ecdh.PublicKey) ([]byte, error) {
	// TODO: We need to figure out how to get X/Y
	x, y := elliptic.Unmarshal(elliptic.P256(), remoteKey.Bytes())

	// We'll be using the SRK for the session encryption, and we need it as the
	// parent for our application key. Make sure it's created and available.
	srkHandle, srkPublic, err := AcquireIdentitySRK(t.tpm, t.i)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(t.tpm, srkHandle)

	// We load the identity into the TPM, using the SRK parent.
	handle, err := LoadIdentityWithParent(t.tpm, *srkHandle, t.i)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(t.tpm, handle.Handle)

	// Add the AuthSession for the handle
	handle.Auth = tpm2.PasswordAuth(t.pin)

	// ECDHZGen command for the TPM, turns the sesion key into something we understand.
	ecdh := tpm2.ECDHZGen{
		KeyHandle: *handle,
		InPoint: tpm2.New2B(
			tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
				Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
			},
		),
	}

	// Execute the ECDHZGen command, we also add session encryption.
	// In this case the session encryption only encrypts the private part going out of the TPM, which is the shared
	// session key we are using in our kdf.
	ecdhRsp, err := ecdh.Execute(t.tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed ecdhzgen: %v", err)
	}

	shared, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed getting ecdh point: %v", err)
	}

	return shared.X.Buffer, nil
}

func NewTPMKeyExchange(tpm transport.TPMCloser, pin []byte, i *Identity) *TPMKeyExchange {
	return &TPMKeyExchange{
		tpm, i, pin,
	}
}
