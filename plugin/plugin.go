package plugin

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	PluginName = "tpm"
)

func getSharedSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	const SRK_HANDLE tpm2.TPMIDHObject = 0x81000001

	srk := tpm2.ReadPublic{
		ObjectHandle: SRK_HANDLE,
	}

	var rsp *tpm2.ReadPublicResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to acquire primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: SRK_HANDLE,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

func createTransientSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
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
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

// Creates a new identity. It initializes a new SRK parent in the TPM and
// returns the identity and the corresponding recipient.
// Note: It does not load the identity key into the TPM.
func CreateIdentity(tpm transport.TPMCloser, pin []byte) (*Identity, *Recipient, error) {
	srkHandle, srkPublic, err := getSharedSRK(tpm)
	if err != nil {
		Log.Printf("failed to acquire shared SRK, falling back to creating transient SRK: %v\n", err)

		srkHandle, srkPublic, err = createTransientSRK(tpm)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create transient SRK (and no shared SRK could be acquired): %v", err)
		}
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
		Version: 2,
		PIN:     pinstatus,
		Private: eccRsp.OutPrivate,
		Public:  eccRsp.OutPublic,
		SRKName: &srkHandle.Name,
	}

	recipient, err := identity.Recipient()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting recipient: %v", err)
	}
	return identity, recipient, nil
}

func LoadIdentity(tpm transport.TPMCloser, identity *Identity) (*tpm2.AuthHandle, error) {
	srkHandle, _, err := AcquireIdentitySRK(tpm, identity)
	if err != nil {
		return nil, err
	}

	defer FlushHandle(tpm, srkHandle)

	return LoadIdentityWithParent(tpm, *srkHandle, identity)
}

func AcquireIdentitySRK(tpm transport.TPMCloser, identity *Identity) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	// Try to use the shared persistent SRK for newer identities
	if identity.Version > 1 {
		srkHandle, srkPublic, err := getSharedSRK(tpm)
		if err == nil && bytes.Equal(srkHandle.Name.Buffer, identity.SRKName.Buffer) {
			return srkHandle, srkPublic, nil
		}
	}

	// Otherwise fall back to trying to create a transient SRK
	srkHandle, srkPublic, err := createTransientSRK(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create transient SRK while trying to acquire identity SRK: %v\n", err)
	}

	// We didn't store the SRK name for identity version 1, so just assume that this SRK is the right one
	if identity.Version == 1 || bytes.Equal(srkHandle.Name.Buffer, identity.SRKName.Buffer) {
		return srkHandle, srkPublic, nil
	}

	return nil, nil, fmt.Errorf("unable to acquire SRK matching name specified by identity")
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
