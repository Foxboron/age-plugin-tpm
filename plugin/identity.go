package plugin

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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

// Identity is the base Identity file for serialziation/deserialization
type Identity struct {
	Version uint8
	PIN     PINStatus
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
	SRKName *tpm2.TPM2BName

	// Private fields for implementation details
	publickey *ecdh.PublicKey
	p         *plugin.Plugin
	tpm       transport.TPMCloser
	pin       func() ([]byte, error)
}

var _ age.Identity = &Identity{}

func (i *Identity) checktpm() bool {
	// We need to check if we have passed a hw device
	// TODO: Figure out a better relationship between identities
	// identity -> TPM enabled identity -> ( TPMTagIdentity || TPMIdentity )
	return i.tpm == nil || i.p == nil
}

func (i *Identity) Callbacks(plugin *plugin.Plugin, tpm transport.TPMCloser, pin func() ([]byte, error)) {
	i.p = plugin
	i.tpm = tpm
	i.pin = pin
}

func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if i.checktpm() {
		panic("missing tpm or age.Plugin access")
	}
	var resp age.Identity
	for _, stanza := range stanzas {
		switch stanza.Type {
		case "p256tag":
			resp = NewTPMTagIdentity(i.tpm, i.pin, i)
		case "tpm-ecc":
			if err := i.p.DisplayMessage("detected old key type. Please migrate to the new p256tag key type"); err != nil {
				return nil, fmt.Errorf("failed displaying message: %v", err)
			}
			resp = NewTPMIdentity(i.tpm, i.pin, i)
		default:
			continue
		}
		return resp.Unwrap([]*age.Stanza{stanza})
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *Identity) Publickey() *ecdh.PublicKey {
	return i.publickey
}

func (i *Identity) Serialize() []any {
	return []interface{}{
		&i.Version,
		&i.PIN,
	}
}

func (i *Identity) Recipient() (*tag.Recipient, error) {
	return NewTagRecipient(i.publickey)
}

func (i *Identity) HasPIN() bool {
	return i.PIN == HasPIN
}

func (i *Identity) String() string {
	var b bytes.Buffer
	for _, v := range i.Serialize() {
		binary.Write(&b, binary.BigEndian, v)
	}

	var pub []byte
	pub = append(pub, tpm2.Marshal(i.Public)...)
	pub = append(pub, tpm2.Marshal(i.Private)...)
	if i.Version > 1 {
		pub = append(pub, tpm2.Marshal(i.SRKName)...)
	}
	b.Write(pub)

	return plugin.EncodeIdentity(PluginName, b.Bytes())
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
		return nil, fmt.Errorf("failed parsing TPMTPublic: %v", err)
	}
	r.Next(len(public.Bytes()) + 2)

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](r.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed parsing TPMTPrivate: %v", err)
	}
	r.Next(len(private.Buffer) + 2)

	key.Public = *public
	key.Private = *private

	// Parse out the public key early
	ecdhKey, err := PublicToECDH(*public)
	if err != nil {
		return nil, err
	}

	key.publickey = ecdhKey

	if key.Version > 1 {
		name, err := tpm2.Unmarshal[tpm2.TPM2BName](r.Bytes())
		if err != nil {
			return nil, err
		}
		key.SRKName = name
	}

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
	return nil, fmt.Errorf("no identities found")
}

var marshalTemplate = `
# Created: %s
`

func Marshal(i *Identity, w io.Writer) {
	s := fmt.Sprintf(marshalTemplate, time.Now())
	s = strings.TrimSpace(s)
	fmt.Fprintf(w, "%s\n", s)
}

func MarshalIdentity(i *Identity, recipient *tag.Recipient, w io.Writer) error {
	Marshal(i, w)
	fmt.Fprintf(w, "# Recipient: %s\n", recipient.String())
	fmt.Fprintf(w, "\n%s\n", i.String())
	return nil
}
