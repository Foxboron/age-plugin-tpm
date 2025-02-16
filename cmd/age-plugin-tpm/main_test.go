package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/spf13/cobra"
)

func TestEncryptDecrypt(t *testing.T) {
	var identity *Identity
	var stanzas []*age.Stanza
	SetLogger()

	tpm, err := plugin.NewSwTPM(t.TempDir())
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	t.Run("Create keys", func(t *testing.T) {
		var generatedKey bytes.Buffer
		pluginOptions = PluginOptions{
			Generate: true,
		}
		if err := RunCli(&cobra.Command{}, tpm.TPM(), os.Stdin, &generatedKey); err != nil {
			t.Fatalf("Failed generating keys")
		}
		fmt.Println(string(generatedKey.Bytes()))
		i, err := plugin.ParseIdentity(&generatedKey)
		if err != nil {
			t.Fatalf("%v", err)
		}
		p, err := page.New("tpm")
		if err != nil {
			t.Fatalf("%v", err)
		}
		identity = &Identity{i, p, tpm.TPM()}
	})

	fileKey := []byte("test")
	t.Run("Encrypt", func(t *testing.T) {
		recipient, err := identity.Recipient()
		if err != nil {
			t.Fatalf("failed getting recipient")
		}
		prcp := &Recipient{recipient}
		stanzas, err = prcp.Wrap(fileKey)
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
