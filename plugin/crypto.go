package plugin

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Functions that deals with the encryption/decryption of the filekey we get from age

// Currently the sender does not utilize the TPM for any crypto operations,
// but the decryption of the filekey for the identity itself does.

const p256Label = "age-encryption.org/v1/tpm-p256"

// Key Dreivative function for age-plugin-tpm
// Sets up a hkdf instance with a salt that contains the shared key and the public key
// Returns an chacha20poly1305 AEAD instance
func kdf(sharedKey, publicKey *ecdh.PublicKey, shared []byte) (cipher.AEAD, error) {
	sharedKeyB := sharedKey.Bytes()
	publicKeyB := publicKey.Bytes()

	// We use the concatinated bytes of the shared key and the public key for the
	// key derivative functions.
	salt := make([]byte, 0, len(sharedKeyB)+len(publicKeyB))
	salt = append(salt, sharedKeyB...)
	salt = append(salt, publicKeyB...)

	h := hkdf.New(sha256.New, shared, salt, []byte(p256Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	return chacha20poly1305.New(wrappingKey)
}

// Unwraps a key using the standard kdf function.
func UnwrapKey(sessionKey, publicKey *ecdh.PublicKey, shared, fileKey []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)

	aead, err := kdf(sessionKey, publicKey, shared)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, fileKey, nil)
}

// Wraps a key using the standard kdf function.
func WrapKey(sessionKey, publicKey *ecdh.PublicKey, shared, fileKey []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)

	aead, err := kdf(sessionKey, publicKey, shared)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, fileKey, nil), nil
}

// Wraps the file key in a session key
// Returns the sealed filekey, the session pubkey bytes, error
func EncryptFileKey(fileKey []byte, pubkey *ecdh.PublicKey) ([]byte, []byte, error) {

	// Create the session key we'll be passing to the stanza
	sessionKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sessionPubKey := sessionKey.PublicKey()

	// Do ECDH for the shared secret
	shared, err := sessionKey.ECDH(pubkey)
	if err != nil {
		return nil, nil, err
	}

	// Wrap the filekey with our aead instance
	b, err := WrapKey(sessionPubKey, pubkey, shared, fileKey)
	if err != nil {
		return nil, nil, err
	}

	// Return the bytes, and the marshalled compressed bytes of the session public
	// key.
	return b, MarshalCompressedEC(sessionPubKey), nil
}

// Decrypts and unwraps a filekey
func DecryptFileKeyTPM(tpm transport.TPMCloser, identity *Identity, remoteKey, fileKey, pin []byte) ([]byte, error) {
	// Unmarshal the compressed ECDH session key we got from the stanza
	x, y, sessionKey, err := UnmarshalCompressedEC(remoteKey)
	if err != nil {
		return nil, err
	}

	// We'll be using the SRK for the session encryption, and we need it as the
	// parent for our application key. Make sure it's created and available.
	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpm, srkHandle)

	// We load the identity into the TPM, using the SRK parent.
	handle, err := LoadIdentityWithParent(tpm, *srkHandle, identity)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpm, handle.Handle)

	// Add the AuthSession for the handle
	handle.Auth = tpm2.PasswordAuth(pin)

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
	ecdhRsp, err := ecdh.Execute(tpm,
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

	resp, err := identity.Recipient()
	if err != nil {
		return nil, err
	}

	// Unwrap the key with the kdf/chacha20
	b, err := UnwrapKey(sessionKey, resp.Pubkey, shared.X.Buffer, fileKey)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Unmarshal a compressed ec key
func UnmarshalCompressedEC(b []byte) (*big.Int, *big.Int, *ecdh.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	ec := ecdsa.PublicKey{
		Curve: elliptic.P256(), X: x, Y: y,
	}
	key, err := ec.ECDH()
	return x, y, key, err
}

// Marshal a compressed EC key
func MarshalCompressedEC(pk *ecdh.PublicKey) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), pk.Bytes())
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}
