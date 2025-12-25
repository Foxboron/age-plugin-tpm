package main

import (
	"bytes"
	"os"
	"testing"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/spf13/cobra"
)

func TestEncryptDecrypt(t *testing.T) {
	var identity *plugin.Identity
	var stanzas []*age.Stanza
	SetLogger()

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	p, err := page.New("tpm")
	if err != nil {
		t.Fatalf("%v", err)
	}

	t.Run("Create keys", func(t *testing.T) {
		var generatedKey bytes.Buffer
		pluginOptions = PluginOptions{
			Generate: true,
		}
		if err := RunCli(&cobra.Command{}, tpm, os.Stdin, &generatedKey); err != nil {
			t.Fatalf("Failed generating keys")
		}
		i, err := plugin.ParseIdentity(&generatedKey)
		if err != nil {
			t.Fatalf("%v", err)
		}
		identity = i
	})

	identity.Callbacks(p, tpm, func() ([]byte, error) { return nil, nil })

	identity.Unwrap(nil)

	fileKey := []byte("test")
	t.Run("Encrypt", func(t *testing.T) {
		recipient, err := identity.Recipient()
		if err != nil {
			t.Fatalf("failed getting recipient")
		}
		stanzas, err = recipient.Wrap(fileKey)
		if err != nil {
			t.Fatal("failed wrapping filekey")
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		f, err := identity.Unwrap(stanzas)
		if err != nil {
			t.Fatalf("failed unwrapping filekey: %v", err)
		}
		if !bytes.Equal(fileKey, f) {
			t.Fatal("filekey are not equal")
		}
	})
}
