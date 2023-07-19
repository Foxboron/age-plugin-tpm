package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {
	tpm, err := NewSwTPM(t.TempDir())
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

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
			shouldfail: true,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			identity, recipient, err1 := CreateIdentity(tpm.TPM(), c.pin)

			wrappedFileKey, sessionKey, err2 := EncryptFileKey(c.filekey, recipient.Pubkey)

			unwrappedFileKey, err3 := DecryptFileKeyTPM(tpm.TPM(), identity, sessionKey, wrappedFileKey, c.decryptpin)

			err := errors.Join(err1, err2, err3)

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if !bytes.Equal(c.filekey, unwrappedFileKey) {
				t.Fatalf("filkeys are not the same")
			}
		})
	}
}
