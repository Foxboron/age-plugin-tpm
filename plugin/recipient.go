package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/foxboron/age-plugin-tpm/internal/bech32"
	"github.com/google/go-tpm/tpmutil"
)

// TODO: This should be extended with a struct
//       Optionally with a reserved field so we could implement
//       other key-types in the future

func EncodeRecipient(handle tpmutil.Handle, pubkey *rsa.PublicKey) (string, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, handle)
	binary.Write(&b, binary.BigEndian, int64(pubkey.E))
	binary.Write(&b, binary.BigEndian, pubkey.N.Bytes())
	return bech32.Encode(RecipientPrefix, b.Bytes())
}

func DecodeRecipient(s string) (tpmutil.Handle, *rsa.PublicKey, error) {
	Log.Printf("'%s'\n", s)
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

	var E int64
	if err := binary.Read(r, binary.BigEndian, &E); err != nil {
		return handle, &rsa.PublicKey{}, err
	}

	var bb bytes.Buffer
	io.Copy(&bb, r)
	N := new(big.Int).SetBytes(bb.Bytes())
	return handle, &rsa.PublicKey{
		N: N,
		E: int(E),
	}, nil
}

// oaep label for the plugin itself
const oaepTPMLabel = "age-encryption.org/v1/ssh-tpm"

func WrapFileKey(fileKey []byte, pubkey *rsa.PublicKey) ([]byte, error) {

	label := []byte(oaepTPMLabel)
	// append a null byte to the label, as it is what the TPM requires
	label = append(label, 0)

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		pubkey, fileKey, label)
	if err != nil {
		return nil, err
	}
	return wrappedKey, nil
}
