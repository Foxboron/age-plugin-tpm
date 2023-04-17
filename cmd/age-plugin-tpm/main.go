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
	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

type PluginOptions struct {
	SwTPM        bool
	AgePlugin    string
	GenerateKey  bool
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
  $ age-plugin-tpm --generate-key -o key.txt
  Public key:
  age1tpm1syqqqpqqqqqqqqqpqqqmjga47cvugu29m30p4tj420v55xszp622jq8zc5ad7clmxwy[...]

  $ echo "Hello World" | age -r "age1tpm1syqqqpqqqqqqqqqpqqqmjga47cvugu29m30p4tj420v55xszp622jq8zc5ad7clmxwy[...]" > secret.age

  $ age --decrypt -i key.txt -o - secret.age
  Hello World`

var (
	pluginOptions = PluginOptions{}
	rootCmd       = &cobra.Command{
		Use:     "age-plugin-tpm",
		Long:    "age-plugin-tpm is a tool to generate age compatible keys with backed by a TPM.",
		Example: example,
		RunE:    RunPlugin,
	}
	tpmPath = "/dev/tpm0"
)

func SetupSwtpm() *swtpm_test.Swtpm {
	dir := "/var/tmp/age-plugin-tpm"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirTemp("/var/tmp", "age-plugin-tpm")
	}
	return swtpm_test.NewSwtpm(dir)
}

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

func RunCli() error {
	var err error
	var swtpm *swtpm_test.Swtpm
	if pluginOptions.SwTPM {
		swtpm = SetupSwtpm()
		tpmPath, err = swtpm.Socket()
		if err != nil {
			return err
		}
		defer swtpm.Stop()
	}

	tpm, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return err
	}
	defer tpm.Close()

	if pluginOptions.GenerateKey {
		k, err := plugin.CreateKey(tpm)
		if err != nil {
			return err
		}
		plugin.SaveKey(k)
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
	}
	if pluginOptions.List {
		keys, err := plugin.GetSavedKeys()
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
		return nil
	}

	if pluginOptions.Identities {
		keys, err := plugin.GetSavedKeys()
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
		return nil
	}
	// TODO: we need to figure this out later
	// this doesn't actually work with age
	if pluginOptions.Decrypt {
		var handle tpmutil.Handle = 0x81000004
		file := "test-decrypt.txt"
		return plugin.Decrypt(tpm, handle, file)
	}
	if pluginOptions.Encrypt {
		var handle tpmutil.Handle = 0x81000004
		return plugin.Encrypt(tpm, handle)
	}
	if pluginOptions.DeleteHandle {
		if pluginOptions.Handle != "" {
			return fmt.Errorf("need to specify --handle before using --delete")
		}
		handle, err := plugin.StringToHandle(pluginOptions.Handle)
		if err != nil {
			return err
		}
		if err := plugin.DeleteKey(tpm, handle); err != nil {
			return fmt.Errorf("failed deleting key: %v", err)
		}
	}
	return nil
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

func b64Encode(s []byte) string {
	return base64.RawStdEncoding.Strict().EncodeToString(s)
}

func RunRecipientV1() error {
	// TODO: Reimplement once we have a proper implementation from upstream
	var entry string
	var key string
	recipients := []string{}
	scanner := bufio.NewScanner(os.Stdin)
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
			_, pubkey, err := plugin.DecodeRecipient(identity)
			if err != nil {
				return err
			}

			fileKey, err := b64Decode(keyB64)
			if err != nil {
				return err
			}

			wrapped, err := plugin.WrapFileKey(fileKey, pubkey)
			if err != nil {
				return err
			}

			os.Stdout.WriteString("-> recipient-stanza 0 tpm-rsa\n")

			// We can only write 48 bytes pr line
			// chunk the output before b64 encoding it
			r := bytes.NewBuffer(wrapped)
			for {
				if r.Len() == 0 {
					break
				}
				b := r.Next(48)
				os.Stdout.WriteString(b64Encode(b) + "\n")
			}
		case "done":
			os.Stdout.WriteString("-> done\n\n")
			break parser
		}
	}
	return nil
}

func RunIdentityV1() error {
	var swtpm *swtpm_test.Swtpm
	var err error
	if pluginOptions.SwTPM {
		swtpm = SetupSwtpm()
		tpmPath, err = swtpm.Socket()
		if err != nil {
			return err
		}
		defer swtpm.Stop()
	}

	tpm, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		plugin.Log.Printf("OpenTPM err")
		return err
	}
	defer tpm.Close()

	var entry string
	identities := []string{}
	scanner := bufio.NewScanner(os.Stdin)
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
				return err
			}

			identity := identities[0]
			k, err := plugin.DecodeKey(identity)
			if err != nil {
				return err
			}

			key, err := plugin.DecryptTPM(tpm, k.Handle, wrappedKey)
			if err != nil {
				return err
			}
			os.Stdout.WriteString("-> file-key 0\n")
			os.Stdout.WriteString(b64Encode(key) + "\n")
		case "done":
			// Age kills us off too quickly to properly shut down swtpm, so do this before returning.
			tpm.Close()
			if pluginOptions.SwTPM {
				swtpm.Stop()
			}
			os.Stdout.WriteString("-> done\n\n")
			break parser
		}
	}
	return nil
}

func RunPlugin(cmd *cobra.Command, args []string) error {
	switch pluginOptions.AgePlugin {
	case "recipient-v1":
		plugin.Log.Println("Got recipient-v1")
		return RunRecipientV1()
	case "identity-v1":
		plugin.Log.Println("Got identity-v1")
		return RunIdentityV1()
	default:
		return RunCli()
	}
}

func pluginFlags(cmd *cobra.Command, opts *PluginOptions) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.BoolVarP(&pluginOptions.GenerateKey, "generate-key", "g", false, "Generate a key on the TPM. Defaults to storing it under handle 0x81000004")
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
	if os.Getenv("AGE_PLUGIN_TPM_SWTPM") != "" {
		pluginOptions.SwTPM = true
	}
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
