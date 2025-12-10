package plugin

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMTagIdentity implements the p256tag identity handler
type TPMTagIdentity struct {
	tpm      transport.TPMCloser
	identity *Identity
	pin      func() ([]byte, error)
}

func NewTPMTagIdentity(tpm transport.TPMCloser, pin func() ([]byte, error), identity *Identity) *TPMTagIdentity {
	return &TPMTagIdentity{tpm, identity, pin}
}

var _ age.Identity = &TPMTagIdentity{}

func (t *TPMTagIdentity) unwrap(block *age.Stanza) ([]byte, error) {
	if len(block.Args) < 2 || block.Type != "p256tag" {
		return nil, age.ErrIncorrectIdentity
	}

	tag, err := b64Decode(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed base64 decode session key: %v", err)
	}

	sessionKey, err := b64Decode(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed base64 decode session key: %v", err)
	}

	rsp, err := t.identity.Recipient()
	if err != nil {
		return nil, fmt.Errorf("unwrap: failed to get recipient from identity %v", err)
	}

	itag, err := rsp.Tag(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap: failed to get tag from recipient: %v", err)
	}

	// Check if we are dealing with the correct key
	if subtle.ConstantTimeCompare(tag, itag) != 1 {
		return nil, age.ErrIncorrectIdentity
	}
	var pin []byte
	if t.identity.HasPIN() {
		pin, err = t.pin()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin: %v", err)
		}
	}

	k, err := hpke.NewDHKEMPrivateKey(NewTPMKeyExchange(t.tpm, pin, t.identity))
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap file key: %v", err)
	}
	r, err := hpke.NewRecipient(sessionKey, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap file key: %v", err)
	}
	return r.Open(nil, block.Body)
}

func (t *TPMTagIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		fileKey, err := t.unwrap(s)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (t *TPMTagIdentity) Recipient() *tag.Recipient {
	resp, err := NewTagRecipient(t.identity.publickey)
	if err != nil {
		panic("this is unexpected")
	}
	return resp
}
