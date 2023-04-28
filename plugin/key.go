package plugin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/foxboron/age-plugin-tpm/internal/bech32"
	"github.com/google/go-tpm/tpmutil"
)

type PINStatus int64

const (
	NoPIN PINStatus = iota
	HasPIN
)

func (p PINStatus) String() string {
	switch p {
	case NoPIN:
		return "NoPIN"
	case HasPIN:
		return "HasPIN"
	}
	return "Not a PINStatus"
}

type Identity struct {
	Version   uint8          `json:"version"`
	Handle    tpmutil.Handle `json:"handle"`
	PIN       PINStatus      `json:"pin"`
	Created   time.Time      `json:"created"`
	Identity  string         `json:"identity"`
	Recipient string         `json:"recipient"`
}

func (i *Identity) HandleToString() string {
	return HandleToString(i.Handle)
}

func (i *Identity) Serialize() []any {
	return []interface{}{
		&i.Version,
		&i.Handle,
	}
}

func DecodeIdentity(s string) (*Identity, error) {
	var key Identity
	hrp, b, err := bech32.Decode(s)
	if err != nil {
		return nil, err
	}
	if hrp != strings.ToUpper(IdentityPrefix) {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.Serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}
	return &key, nil
}

func EncodeIdentity(i *Identity) (string, error) {
	var b bytes.Buffer
	for _, v := range i.Serialize() {
		if err := binary.Write(&b, binary.BigEndian, v); err != nil {
			return "", err
		}
	}
	s, err := bech32.Encode(strings.ToUpper(IdentityPrefix), b.Bytes())
	if err != nil {
		return "", err
	}
	return s, nil
}

var (
	marshalTemplate = `
# Handle: %s
# Created: %s
`
)

func Marshal(i *Identity, w io.Writer) {
	s := fmt.Sprintf(marshalTemplate, i.HandleToString(), i.Created)
	s = strings.TrimSpace(s)
	fmt.Fprintf(w, "%s\n", s)
}

func MarshalIdentity(i *Identity, w io.Writer) error {
	key, err := EncodeIdentity(i)
	if err != nil {
		return err
	}
	Marshal(i, w)
	fmt.Fprintf(w, "# Recipient: %s\n", strings.ToLower(i.Recipient))
	fmt.Fprintf(w, "\n%s\n", key)
	return nil
}

func MarshalRecipient(i *Identity, w io.Writer) error {
	Marshal(i, w)
	fmt.Fprintf(w, "%s\n", strings.ToLower(i.Recipient))
	return nil
}
