package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/spf13/cobra"
)

func Setup(t *testing.T) {
	// Override the CLI swtpmPath to a test dir
	swtpmPath = t.TempDir()

	// Ensure we write the config.json to a temp directory
	os.Setenv("XDG_CACHE_HOME", t.TempDir())
	os.Setenv("AGE_PLUGIN_TPM_SWTPM", "1")
	SetLogger()
}

func TestEncryptDecrypt(t *testing.T) {
	Setup(t)

	var wrappedKey string

	fileKey := []byte("test")

	t.Run("Generate key", func(t *testing.T) {
		// Silence the key generation Marshal
		// TODO: Should be done better
		sout := os.Stdout
		null, _ := os.Open(os.DevNull)
		os.Stdout = null
		// First generate a key
		pluginOptions = PluginOptions{
			GenerateKey: true,
			// TODO: We need to do this elsewhere
			SwTPM: true,
		}

		err := RunCli(&cobra.Command{})
		os.Stdout = sout
		if err != nil {
			t.Fatalf("Failed generating keys")
		}
	})

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

		if err := RunIdentityV1(&stdin, &stdout); err != nil {
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
