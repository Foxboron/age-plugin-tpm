package plugin

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"filippo.io/nistec"
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
	point, err := nistec.NewP256Point().SetBytes(pk.Bytes())
	if err != nil {
		panic("invalid compressed ec point")
	}
	return point.BytesCompressed()
}

func xyECC(p []byte) ([]byte, []byte) {
	if p[0] != 4 {
		panic("p256 key is not a p256 key")
	}
	return p[1 : 32+1], p[1+32:]
}
