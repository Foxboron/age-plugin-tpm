package plugin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/foxboron/age-plugin-tpm/internal/bech32"
	"github.com/google/go-tpm/tpm2"
)

type Recipient struct {
	Pubkey *ecdh.PublicKey
	tag    []byte
}

// Returns the 4 first bytes of a sha256 sum of the key
// this is used to to find the correct identity in a stanza
func (r *Recipient) Tag() []byte {
	return r.tag
}

func (r *Recipient) String() string {
	return EncodeRecipient(r)
}

func NewRecipient(ecc *ecdh.PublicKey) *Recipient {
	sum := sha256.Sum256(ecc.Bytes())
	return &Recipient{
		Pubkey: ecc,
		tag:    sum[:4],
	}
}

func NewRecipientFromBytes(s []byte) (*Recipient, error) {
	c := tpm2.BytesAs2B[tpm2.TPMTPublic](s)
	pub, err := c.Contents()
	if err != nil {
		return nil, err
	}
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	ecdhKey, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(),
		big.NewInt(0).SetBytes(ecc.X.Buffer),
		big.NewInt(0).SetBytes(ecc.Y.Buffer),
	))
	if err != nil {
		return nil, err
	}

	return NewRecipient(ecdhKey), nil
}

func EncodeRecipient(recipient *Recipient) string {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, MarshalCompressedEC(recipient.Pubkey))
	recp, _ := bech32.Encode(RecipientPrefix, b.Bytes())
	return recp
}

func MarshalRecipient(pubkey *Recipient, w io.Writer) error {
	recipient := EncodeRecipient(pubkey)
	fmt.Fprintf(w, "%s\n", recipient)
	return nil
}

func DecodeRecipient(s string) (*Recipient, error) {
	hrp, b, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("DecodeRecipinet: failed to decode bech32: %v", err)
	}

	if hrp != RecipientPrefix {
		return nil, fmt.Errorf("invalid hrp")
	}

	_, _, ecdhKey, err := UnmarshalCompressedEC(b)
	if err != nil {
		return nil, err
	}

	return NewRecipient(ecdhKey), nil
}
