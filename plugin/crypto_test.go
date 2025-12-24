package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"filippo.io/age/plugin"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestEncryptionDecryption(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	SetLogger(io.Discard)

	cases := []struct {
		msg        string
		filekey    []byte
		pin        []byte
		decryptpin []byte
		shouldfail bool
	}{
		{
			msg:     "test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
		},
		{
			msg:        "test encryption/decrypt - pin",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			decryptpin: []byte("123"),
		},
		{
			msg:        "test encryption/decrypt - no pin for decryption",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
		},
		{
			msg:        "test encryption/decrypt - no pin for key, pin for decryption",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte(""),
			decryptpin: []byte("123"),
			shouldfail: false,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			identity, _, err1 := CreateIdentity(tpm, c.pin)
			identity.Callbacks(&plugin.Plugin{}, tpm, func() ([]byte, error) { return c.decryptpin, nil })
			recipient := identity.TPMRecipient()

			stanzas, err2 := recipient.Wrap(c.filekey)
			unwrappedFileKey, err3 := identity.Unwrap(stanzas)

			err := errors.Join(err1, err2, err3)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			if !bytes.Equal(c.filekey, unwrappedFileKey) {
				t.Fatalf("filkeys are not the same")
			}
		})
	}
}
