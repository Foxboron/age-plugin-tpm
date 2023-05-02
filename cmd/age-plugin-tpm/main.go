package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/spf13/cobra"
)

type PluginOptions struct {
	SwTPM        bool
	AgePlugin    string
	Generate     bool
	List         bool
	Identities   bool
	Decrypt      bool
	Encrypt      bool
	DeleteHandle bool
	OutputFile   string
	LogFile      string
	Handle       string
}

var example = `
  $ age-plugin-tpm --generate -o age-identity.txt
  # Handle: 0x81000004
  # Created: 2023-04-29 13:33:37 +0200 CEST
  # Recipient: age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy

  AGE-PLUGIN-TPM-1QXQSQQQY2HCVDY

  $ echo "Hello World" | age -r "age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy" > secret.age

  $ age --decrypt -i age-identity.txt -o - secret.age
  Hello World`

var (
	swtpmPath     = "/var/tmp/age-plugin-tpm"
	pluginOptions = PluginOptions{}
	rootCmd       = &cobra.Command{
		Use:     "age-plugin-tpm",
		Long:    "age-plugin-tpm is a tool to generate age compatible identities backed by a TPM.",
		Example: example,
		RunE:    RunPlugin,
	}
)

func SetLogger() {
	var w io.Writer
	if pluginOptions.LogFile != "" {
		w, _ = os.Open(pluginOptions.LogFile)
	} else if os.Getenv("AGEDEBUG") != "" {
		w = os.Stderr
	} else {
		w = io.Discard
	}
	plugin.SetLogger(w)
}

func RunCli(cmd *cobra.Command, tpm io.ReadWriteCloser) error {
	switch {
	case pluginOptions.Generate:
		k, err := plugin.CreateIdentity(tpm)
		if err != nil {
			return err
		}
		plugin.SaveIdentity(k)
		if err = plugin.MarshalIdentity(k, os.Stdout); err != nil {
			return err
		}
		if pluginOptions.OutputFile != "" {
			f, err := os.Open(pluginOptions.OutputFile)
			if err != nil {
				return err
			}
			if err = plugin.MarshalIdentity(k, f); err != nil {
				return err
			}
		}

	case pluginOptions.List:
		keys, err := plugin.GetSavedIdentities()
		if err != nil {
			return err
		}
		for _, k := range keys {
			if !plugin.HasKey(tpm, k.Handle) {
				continue
			}
			if err = plugin.MarshalRecipient(k, os.Stdout); err != nil {
				return err
			}
		}

	case pluginOptions.Identities:
		keys, err := plugin.GetSavedIdentities()
		if err != nil {
			return err
		}
		for _, k := range keys {
			if !plugin.HasKey(tpm, k.Handle) {
				continue
			}
			if err = plugin.MarshalIdentity(k, os.Stdout); err != nil {
				return err
			}
		}

	case pluginOptions.DeleteHandle:
		if pluginOptions.Handle == "" {
			return fmt.Errorf("need to specify --handle before using --delete")
		}
		handle, err := plugin.StringToHandle(pluginOptions.Handle)
		if err != nil {
			return err
		}
		if err := plugin.DeleteHandle(tpm, handle); err != nil {
			return fmt.Errorf("failed deleting key: %v", err)
		}
		k, err := plugin.GetIdentity(handle)
		if err != nil {
			return err
		}
		if err := plugin.DeleteIdentity(k); err != nil {
			return fmt.Errorf("failed deleting key: %v", err)
		}
		return nil
	default:
		return cmd.Help()
	}
	return nil
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

func b64Encode(s []byte) string {
	return base64.RawStdEncoding.Strict().EncodeToString(s)
}

func RunRecipientV1(stdin io.Reader, stdout io.StringWriter) error {
	// TODO: Reimplement once we have a proper implementation from upstream
	var entry string
	var key string
	recipients := []string{}
	scanner := bufio.NewScanner(stdin)
parser:
	for scanner.Scan() {
		entry = scanner.Text()
		if len(entry) == 0 {
			continue
		}
		entry = strings.TrimPrefix(entry, "-> ")
		cmd := strings.SplitN(entry, " ", 2)
		plugin.Log.Printf("scanned: '%s'\n", cmd[0])
		switch cmd[0] {
		case "add-recipient":
			// Only one recipient?
			plugin.Log.Printf("add-recipient: %s\n", cmd[1])
			recipients = append(recipients, cmd[1])
		case "wrap-file-key":
			scanner.Scan()
			keyB64 := scanner.Text()
			plugin.Log.Printf("wrap-file-key: %s\n", key)

			// TODO: Support multiple identities
			identity := recipients[0]
			pubkey, err := plugin.DecodeRecipient(identity)
			if err != nil {
				return err
			}

			fileKey, err := b64Decode(keyB64)
			if err != nil {
				return err
			}

			wrapped, sessionKey, err := plugin.WrapFileKey(fileKey, pubkey)
			if err != nil {
				return err
			}

			stdout.WriteString(fmt.Sprintf("-> recipient-stanza 0 tpm-ecc %s\n", b64Encode(sessionKey)))

			// We can only write 48 bytes pr line
			// chunk the output before b64 encoding it
			r := bytes.NewBuffer(wrapped)
			for {
				if r.Len() == 0 {
					break
				}
				b := r.Next(48)
				stdout.WriteString(b64Encode(b) + "\n")
			}
		case "done":
			stdout.WriteString("-> done\n\n")
			break parser
		}
	}
	return nil
}

func RunIdentityV1(tpm io.ReadWriteCloser, stdin io.Reader, stdout io.StringWriter) error {
	var entry string
	identities := []string{}
	scanner := bufio.NewScanner(stdin)
parser:
	for scanner.Scan() {
		entry = scanner.Text()
		if len(entry) == 0 {
			continue
		}
		entry = strings.TrimPrefix(entry, "-> ")
		cmd := strings.SplitN(entry, " ", 2)
		plugin.Log.Printf("scanned: '%s'\n", cmd[0])
		switch cmd[0] {
		case "add-identity":
			plugin.Log.Printf("add-identity: %s\n", cmd[1])
			identities = append(identities, cmd[1])
		case "recipient-stanza":
			plugin.Log.Printf("recipieint-stanza: %s\n", cmd)

			entry := scanner.Text()
			entry = strings.TrimPrefix(entry, "-> ")
			stanza := strings.Split(entry, " ")

			sessionKey, err := b64Decode(stanza[3])
			if err != nil {
				return fmt.Errorf("failed base64 decode session key: %v", err)
			}
			// The bytes are truncated to 64 pr line
			WrappedKeyS := ""
			for scanner.Scan() {
				entry = scanner.Text()
				WrappedKeyS += entry
				if len(entry) < 64 {
					break
				}
			}

			plugin.Log.Printf("read wrapped key: %s", WrappedKeyS)
			wrappedKey, err := b64Decode(WrappedKeyS)
			if err != nil {
				return fmt.Errorf("failed base64 decode wrappedKey: %v", err)
			}

			identity := identities[0]
			k, err := plugin.DecodeIdentity(identity)
			if err != nil {
				return err
			}

			key, err := plugin.DecryptTPM(tpm, k.Handle, sessionKey, wrappedKey)
			if err != nil {
				return err
			}
			stdout.WriteString("-> file-key 0\n")
			stdout.WriteString(b64Encode(key) + "\n")
		case "done":
			// Age kills us off too quickly to properly shut down swtpm, so do this before returning.
			stdout.WriteString("-> done\n\n")
			break parser
		}
	}
	return nil
}

func RunPlugin(cmd *cobra.Command, args []string) error {
	var tpm *plugin.TPMDevice
	var tpmPath string
	var err error
	if pluginOptions.SwTPM || os.Getenv("AGE_PLUGIN_TPM_SWTPM") != "" {
		tpm, err = plugin.NewSwTPM(swtpmPath)
	} else {
		tpm, err = plugin.NewTPM(tpmPath)
	}
	if err != nil {
		return err
	}

	tpm.Watch()
	defer tpm.Close()

	switch pluginOptions.AgePlugin {
	case "recipient-v1":
		plugin.Log.Println("Got recipient-v1")
		return RunRecipientV1(os.Stdin, os.Stdout)
	case "identity-v1":
		plugin.Log.Println("Got identity-v1")
		return RunIdentityV1(tpm.TPM(), os.Stdin, os.Stdout)
	default:
		return RunCli(cmd, tpm.TPM())
	}
}

func pluginFlags(cmd *cobra.Command, opts *PluginOptions) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.BoolVarP(&pluginOptions.Generate, "generate", "g", false, "Generate a identity on the TPM. Defaults to storing it under handle 0x81000004")
	flags.BoolVarP(&pluginOptions.List, "list", "l", false, "List recipients for age identities backed by the TPM.")
	flags.BoolVarP(&pluginOptions.Identities, "identity", "i", false, "List age identities stored in the TPM.")
	flags.StringVarP(&pluginOptions.OutputFile, "output", "o", "", "Write the result to the file.")

	flags.BoolVar(&pluginOptions.DeleteHandle, "delete", false, "Delete a handle from the TPM. Needs to be formatted as hex.")
	flags.StringVar(&pluginOptions.Handle, "handle", "", "Specify which handle to use. Example: 0x81000004.")

	// Debug or logging stuff
	flags.StringVar(&pluginOptions.LogFile, "log-file", "", "Logging file for debug output")

	// SWTPM functionality
	flags.BoolVar(&pluginOptions.SwTPM, "swtpm", false, "Use a software TPM for key storage (Testing only and requires swtpm installed)")

	// Hidden commands
	flags.BoolVar(&pluginOptions.Decrypt, "decrypt", false, "wip")
	flags.BoolVar(&pluginOptions.Encrypt, "encrypt", false, "wip")
	flags.StringVar(&pluginOptions.AgePlugin, "age-plugin", "", "internal use")
	flags.MarkHidden("decrypt")
	flags.MarkHidden("encrypt")
	flags.MarkHidden("age-plugin")
}

func main() {
	SetLogger()
	pluginFlags(rootCmd, &pluginOptions)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
