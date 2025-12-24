package plugin

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"filippo.io/nistec"
	"github.com/google/go-tpm/tpm2"
)

func NewTagRecipientFromBytes(s []byte) (*tag.Recipient, error) {
	ecdhKey, err := PublicToECDH(tpm2.BytesAs2B[tpm2.TPMTPublic](s))
	if err != nil {
		return nil, err
	}
	return NewTagRecipient(ecdhKey)
}

func NewTagRecipient(ecc *ecdh.PublicKey) (*tag.Recipient, error) {
	return tag.NewClassicRecipient(MarshalCompressedEC(ecc))
}

type TPMRecipient struct {
	Pubkey *ecdh.PublicKey
	tag    []byte
}

func (r *TPMRecipient) Tag() []byte {
	return r.tag
}

func (r *TPMRecipient) Bytes() []byte {
	p, err := nistec.NewP256Point().SetBytes(r.Pubkey.Bytes())
	if err != nil {
		panic("internal error: invalid P-256 public key")
	}
	return p.BytesCompressed()
}

func (r *TPMRecipient) String() string {
	return plugin.EncodeRecipient(PluginName, r.Bytes())
}

func (r *TPMRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	wrapped, sessionKey, err := EncryptFileKey(fileKey, r.Pubkey)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: "tpm-ecc",
		Args: []string{b64Encode(r.Tag()), b64Encode(sessionKey)},
		Body: wrapped,
	}}, nil
}

func NewTPMRecipient(ecc *ecdh.PublicKey) *TPMRecipient {
	sum := sha256.Sum256(ecc.Bytes())
	return &TPMRecipient{
		Pubkey: ecc,
		tag:    sum[:4],
	}
}

func ParseTPMRecipient(s string) (*TPMRecipient, error) {
	name, b, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient: %v", err)
	}
	if name != PluginName {
		return nil, fmt.Errorf("invalid plugin for type %s", name)
	}
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil {
		return nil, err
	}
	pubkey, err := ecdh.P256().NewPublicKey(p.Bytes())
	if err != nil {
		return nil, err
	}
	return NewTPMRecipient(pubkey), nil
}

func MarshalRecipient(recipient *tag.Recipient, w io.Writer) error {
	fmt.Fprintf(w, "%s\n", recipient.String())
	return nil
}
