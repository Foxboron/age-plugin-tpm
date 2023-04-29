package plugin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/foxboron/age-plugin-tpm/internal/bech32"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// TODO: This should be extended with a struct
//       Optionally with a reserved field so we could implement
//       other key-types in the future

func EncodeRecipient(handle tpmutil.Handle, pubkey *ecdh.PublicKey) (string, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, handle)
	binary.Write(&b, binary.BigEndian, MarshalCompressedECDH(pubkey))
	return bech32.Encode(RecipientPrefix, b.Bytes())
}

func DecodeRecipient(s string) (tpmutil.Handle, *ecdh.PublicKey, error) {
	hrp, b, err := bech32.Decode(s)
	if err != nil {
		return 0, nil, fmt.Errorf("DecodeRecipinet: failed to decode bech32: %v", err)
	}

	if hrp != RecipientPrefix {
		return 0, nil, fmt.Errorf("invalid hrp")
	}

	r := bytes.NewBuffer(b)

	var handle tpmutil.Handle
	if err := binary.Read(r, binary.BigEndian, &handle); err != nil {
		return 0, nil, err
	}

	var bb bytes.Buffer
	io.Copy(&bb, r)
	_, _, ecdhKey, err := UnmarshalCompressedECDH(bb.Bytes())
	if err != nil {
		return handle, nil, err
	}

	return handle, ecdhKey, nil
}

const p256Label = "age-encryption.org/v1/tpm-p256"

// Wraps the file key in a session key
// Returns  the sealed filekey, the session pubkey bytes, error
func WrapFileKey(fileKey []byte, pubkey *ecdh.PublicKey) ([]byte, []byte, error) {

	sessionKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sessionPubKey := sessionKey.PublicKey()

	shared, err := sessionKey.ECDH(pubkey)
	if err != nil {
		return nil, nil, err
	}

	ourKey := sessionPubKey.Bytes()
	theirKey := pubkey.Bytes()

	salt := make([]byte, 0, len(ourKey)+len(theirKey))
	salt = append(salt, ourKey...)
	salt = append(salt, theirKey...)

	h := hkdf.New(sha256.New, shared[:], salt, []byte(p256Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, fileKey, nil), MarshalCompressedECDH(sessionPubKey), nil
}
