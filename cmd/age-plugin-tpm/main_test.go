package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"regexp"
	"testing"

	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/spf13/cobra"
)

func TestEncryptDecrypt(t *testing.T) {
	var wrappedKey string
	var sessionKey string
	var tag string

	var identity *plugin.Identity

	os.Setenv("XDG_CACHE_HOME", t.TempDir())
	SetLogger()

	tpm, err := plugin.NewSwTPM(t.TempDir())
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	t.Run("Generate key", func(t *testing.T) {
		var generatedKey bytes.Buffer

		pluginOptions = PluginOptions{
			Generate: true,
		}

		err := RunCli(&cobra.Command{}, tpm.TPM(), os.Stdin, &generatedKey)
		if err != nil {
			t.Fatalf("Failed generating keys")
		}

		identity, err = plugin.ParseIdentity(&generatedKey)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	fileKey := []byte("test")

	t.Run("RunRecipientV1", func(t *testing.T) {
		var stdin bytes.Buffer
		var stdout strings.Builder

		pubkey, err := plugin.GetPubkey(tpm.TPM(), identity)
		if err != nil {
			t.Fatalf("failed getting public key: %v", err)
		}
		recipient := plugin.EncodeRecipient(pubkey)

		stdin.WriteString("-> add-recipient ")
		stdin.WriteString(recipient + "\n")
		stdin.WriteString("-> wrap-file-key\n")
		stdin.WriteString(b64Encode(fileKey) + "\n")
		stdin.WriteString("-> done\n")
		if err := RunRecipientV1(&stdin, &stdout); err != nil {
			t.Fatalf("Failed RunRecipientV1: %v", err)
		}

		match := regexp.
			MustCompile(`(?m)-> recipient-stanza 0 tpm-ecc (.+?) (.+?)\n(.+?)\n-> done`).
			FindStringSubmatch(stdout.String())

		tag, sessionKey, wrappedKey = match[1], match[2], match[3]

	})

	t.Run("RunIdentitiyV1", func(t *testing.T) {
		var stdin bytes.Buffer
		var stdout strings.Builder

		encoded, err := plugin.EncodeIdentity(identity)
		if err != nil {
			t.Fatalf("Failed EncodeKey: %v", err)
		}

		stdin.WriteString(fmt.Sprintf("-> add-identity %s\n", encoded))
		stdin.WriteString(fmt.Sprintf("-> recipient-stanza 0 tpm-ecc %s %s\n", tag, sessionKey))
		stdin.WriteString(wrappedKey + "\n")
		stdin.WriteString("-> done\n")

		if err := RunIdentityV1(tpm.TPM(), &stdin, &stdout); err != nil {
			t.Fatalf("Failed RunRecipientV1: %v", err)
		}

		output := regexp.
			MustCompile(`(?m)-> file-key 0\n(.+?)\n-> done`).
			FindStringSubmatch(stdout.String())[1]

		out, err := b64Decode(output)
		if err != nil {
			t.Fatalf("b64Decode failed: %v", err)
		}

		if !bytes.Equal(fileKey, out) {
			t.Fatalf("RunIdentityV1 failed decryption")
		}
	})
}
