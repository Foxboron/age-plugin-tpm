package plugin

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age/plugin"
	"github.com/google/go-tpm/tpm2"
)

// We need to know if the TPM handle has a pin set
type PINStatus uint8

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
	Version uint8
	PIN     PINStatus
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
}

func (i *Identity) Serialize() []any {
	return []interface{}{
		&i.Version,
		&i.PIN,
	}
}

func (i *Identity) Recipient() (*Recipient, error) {
	return NewRecipientFromBytes(i.Public.Bytes())
}

func DecodeIdentity(s string) (*Identity, error) {
	var key Identity
	name, b, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != PluginName {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.Serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](r.Bytes())
	if err != nil {
		return nil, err
	}

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](r.Bytes()[len(public.Bytes())+2:])
	if err != nil {
		return nil, err
	}

	key.Public = *public
	key.Private = *private

	return &key, nil
}

func ParseIdentity(f io.Reader) (*Identity, error) {
	// Same parser as age
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		identity, err := DecodeIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		return identity, nil
	}
	return nil, fmt.Errorf("no identites found")
}

func EncodeIdentity(i *Identity) string {
	var b bytes.Buffer
	for _, v := range i.Serialize() {
		binary.Write(&b, binary.BigEndian, v)
	}

	var pub []byte
	pub = append(pub, tpm2.Marshal(i.Public)...)
	pub = append(pub, tpm2.Marshal(i.Private)...)
	b.Write(pub)

	return plugin.EncodeIdentity(PluginName, b.Bytes())
}

var (
	marshalTemplate = `
# Created: %s
`
)

func Marshal(i *Identity, w io.Writer) {
	s := fmt.Sprintf(marshalTemplate, time.Now())
	s = strings.TrimSpace(s)
	fmt.Fprintf(w, "%s\n", s)
}

func MarshalIdentity(i *Identity, recipient *Recipient, w io.Writer) error {
	Marshal(i, w)
	fmt.Fprintf(w, "# Recipient: %s\n", recipient)
	fmt.Fprintf(w, "\n%s\n", EncodeIdentity(i))
	return nil
}
