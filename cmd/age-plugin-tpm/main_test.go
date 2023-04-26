package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

var (
	// TODO: Still an hardcoded handle
	handle tpmutil.Handle = 0x81000004
)

func TestEncryptDecrypt(t *testing.T) {
	var wrappedKey string

	os.Setenv("XDG_CACHE_HOME", t.TempDir())
	SetLogger()

	tpm, err := plugin.NewSwTPM(t.TempDir())
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	t.Run("Generate key", func(t *testing.T) {
		// Silence the key generation Marshal
		// TODO: Should be done better
		sout := os.Stdout
		null, _ := os.Open(os.DevNull)
		os.Stdout = null
		// First generate a key
		pluginOptions = PluginOptions{
			GenerateKey: true,
		}

		err := RunCli(&cobra.Command{}, tpm.TPM())
		os.Stdout = sout
		if err != nil {
			t.Fatalf("Failed generating keys")
		}
	})

	fileKey := []byte("test")

	t.Run("RunRecipientV1", func(t *testing.T) {
		var stdin bytes.Buffer
		var stdout strings.Builder

		s := b64Encode(fileKey)

		key, err := plugin.GetKey(0x81000004)
		if err != nil {
			t.Fatalf("Failed GetKey: %v", err)
		}
		stdin.WriteString("-> add-recipient ")
		stdin.WriteString(key.Recipient + "\n")
		stdin.WriteString("-> wrap-file-key\n")
		stdin.WriteString(s + "\n")
		stdin.WriteString("-> done\n")
		if err := RunRecipientV1(&stdin, &stdout); err != nil {
			t.Fatalf("Failed RunRecipientV1: %v", err)
		}

		// TODO: Better parsing
		output := strings.TrimSpace(stdout.String())
		output = strings.ReplaceAll(output, "-> recipient-stanza 0 tpm-rsa\n", "")
		output = strings.ReplaceAll(output, "-> done", "")
		wrappedKey = output
	})

	t.Run("RunIdentitiyv1", func(t *testing.T) {
		var stdin bytes.Buffer
		var stdout strings.Builder

		key, err := plugin.GetKey(0x81000004)
		if err != nil {
			t.Fatalf("Failed GetKey: %v", err)
		}

		identity, err := plugin.EncodeKey(key)
		if err != nil {
			t.Fatalf("Failed EncodeKey: %v", err)
		}

		stdin.WriteString(fmt.Sprintf("-> add-identity %s\n", identity))
		stdin.WriteString("-> recipient-stanza 0 tpm-rsa\n")
		stdin.WriteString(wrappedKey)
		stdin.WriteString("-> done\n")

		if err := RunIdentityV1(tpm.TPM(), &stdin, &stdout); err != nil {
			t.Fatalf("Failed RunRecipientV1: %v", err)
		}

		// TODO: Better parsing
		output := strings.TrimSpace(stdout.String())
		output = strings.ReplaceAll(output, "-> file-key 0\n", "")
		output = strings.ReplaceAll(output, "-> done", "")
		out, err := b64Decode(output)
		if err != nil {
			t.Fatalf("b64Decode failed: %v", err)
		}

		if !bytes.Equal(fileKey, out) {
			t.Fatalf("RunIdentityV1 failed decryption")
		}
	})
}
