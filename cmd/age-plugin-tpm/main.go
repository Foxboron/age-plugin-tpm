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
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type PluginOptions struct {
	SwTPM      bool
	AgePlugin  string
	Convert    bool
	Generate   bool
	Decrypt    bool
	Encrypt    bool
	OutputFile string
	LogFile    string
	PIN        bool
}

var example = `
  $ age-plugin-tpm --generate -o age-identity.txt
  # Created: 2023-07-10 22:13:57.864450969 +0200 CEST m=+0.475252114
  # Recipient: age1tpm1qt92lcdxj75rjz9e4t9nud7fv6t2cfn8rhzdfnc0z2rnfgv3cqwrqgme4dq

  AGE-PLUGIN-TPM-1QYQQQKQQYVQQKQQZQPEQQQQQZQQPJQQTQQPSQYQQYR92LCDXJ75RJZ9E4T9NUD7[...]

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

func clearLine(out io.Writer) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)
	fmt.Fprintf(out, "\r\n"+CPL+EL)
}

func GetPin(prompt string) ([]byte, error) {
	fmt.Printf("%s ", prompt)
	return term.ReadPassword(int(os.Stdin.Fd()))
}

func RunCli(cmd *cobra.Command, tpm transport.TPMCloser, in io.Reader, out io.Writer) error {
	var pin []byte
	var err error
	switch {
	case pluginOptions.Generate:

		if pluginOptions.PIN {
			if s := os.Getenv("AGE_TPM_PIN"); s != "" {
				pin = []byte(s)
			} else {
				pin, err = GetPin("Enter pin for key:")
				if err != nil {
					return err
				}

				clearLine(os.Stdin)

				confirm, err := GetPin("Confirm pin:")
				if err != nil {
					return err
				}
				if !bytes.Equal(pin, confirm) {
					return fmt.Errorf("pins didn't match")
				}
			}
		}
		if pluginOptions.OutputFile != "" && pluginOptions.OutputFile != "-" {
			f, err := os.OpenFile(pluginOptions.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
		}

		identity, recipient, err := plugin.CreateIdentity(tpm, pin)
		if err != nil {
			return err
		}
		if err = plugin.MarshalIdentity(identity, recipient, out); err != nil {
			return err
		}
	case pluginOptions.Convert:
		identity, err := plugin.ParseIdentity(in)
		if err != nil {
			return err
		}
		recipient, err := identity.Recipient()
		if err != nil {
			return err
		}
		return plugin.MarshalRecipient(recipient, out)
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
			recipient, err := plugin.DecodeRecipient(identity)
			if err != nil {
				return err
			}

			fileKey, err := b64Decode(keyB64)
			if err != nil {
				return err
			}

			wrapped, sessionKey, err := plugin.EncryptFileKey(fileKey, recipient.Pubkey)
			if err != nil {
				return err
			}

			stdout.WriteString(fmt.Sprintf("-> recipient-stanza 0 tpm-ecc %s %s\n", b64Encode(recipient.Tag()), b64Encode(sessionKey)))

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
			break parser
		}
	}

	stdout.WriteString("-> done\n\n")
	return nil
}

type RecipientStanza struct {
	SessionKey []byte
	WrappedKey []byte
	Tag        []byte
	Identity   *plugin.Identity
}

func RunIdentityV1(tpm transport.TPMCloser, stdin io.Reader, stdout io.StringWriter) error {
	var entry string
	identities := []string{}
	recipients := []*RecipientStanza{}
	scanner := bufio.NewScanner(stdin)
parser:
	for scanner.Scan() {
		entry = scanner.Text()
		plugin.Log.Printf("scanned: '%s'\n", entry)
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
			plugin.Log.Printf("recipient-stanza: %s\n", cmd)

			entry := scanner.Text()
			entry = strings.TrimPrefix(entry, "-> ")
			stanza := strings.Split(entry, " ")

			// The bytes are truncated to 64 pr line
			WrappedKeyS := ""
			for scanner.Scan() {
				entry = scanner.Text()
				WrappedKeyS += entry
				if len(entry) < 64 {
					break
				}
			}

			// We need at least 5 elements
			if len(stanza) > 5 {
				plugin.Log.Println("wrong number of arguments")
				continue
			}

			// We only understand "tpm-ecc" stanzas
			if stanza[2] != "tpm-ecc" {
				plugin.Log.Println("not a tpm-ecc key")
				continue
			}

			tag, err := b64Decode(stanza[3])
			if err != nil {
				return fmt.Errorf("failed base64 decode session key: %v", err)
			}

			sessionKey, err := b64Decode(stanza[4])
			if err != nil {
				return fmt.Errorf("failed base64 decode session key: %v", err)
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
			recipients = append(recipients, &RecipientStanza{
				SessionKey: sessionKey,
				WrappedKey: wrappedKey,
				Tag:        tag,
				Identity:   k,
			})
		case "done":
			// Consume last new line?
			scanner.Scan()
			break parser
		}
	}

	for _, recipient := range recipients {
		var pin []byte
		var err error

		if recipient.Identity.PIN == plugin.HasPIN {
			if s := os.Getenv("AGE_TPM_PIN"); s != "" {
				pin = []byte(s)
			} else if s := os.Getenv("AGE_TPM_PINENTRY"); s != "" {
				pin, err = plugin.GetPinentry()
				if err != nil {
					return err
				}
			} else {
				stdout.WriteString("-> request-secret tpm\n")
				stdout.WriteString(b64Encode([]byte("Please enter the PIN for the key:")) + "\n")
			loop:
				for scanner.Scan() {
					switch scanner.Text() {
					case "-> ok":
						scanner.Scan()
						entry, err := b64Decode(scanner.Text())
						if err != nil {
							return err
						}
						pin = entry
						break loop
					}
				}
			}
		}

		resp, err := recipient.Identity.Recipient()
		if err != nil {
			return fmt.Errorf("failed to get recipient for identity: %v", err)
		}

		// Check if we are dealing with the correct key
		if !bytes.Equal(recipient.Tag, resp.Tag()) {
			continue
		}

		key, err := plugin.DecryptFileKeyTPM(tpm, recipient.Identity, recipient.SessionKey, recipient.WrappedKey, pin)
		if err != nil {
			return err
		}
		stdout.WriteString("-> file-key 0\n")
		stdout.WriteString(b64Encode([]byte(key)) + "\n")
	}
	stdout.WriteString("-> done\n\n")
	return nil
}

func RunPlugin(cmd *cobra.Command, args []string) error {
	var tpm *plugin.TPMDevice
	var tpmPath string
	var err error
	if pluginOptions.SwTPM || os.Getenv("AGE_TPM_SWTPM") != "" {
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
		if err := RunRecipientV1(os.Stdin, os.Stdout); err != nil {
			os.Stdout.WriteString("-> error\n")
			os.Stdout.WriteString(b64Encode([]byte(err.Error())) + "\n")
			return err
		}
	case "identity-v1":
		plugin.Log.Println("Got identity-v1")
		if err := RunIdentityV1(tpm.TPM(), os.Stdin, os.Stdout); err != nil {
			os.Stdout.WriteString("-> error\n")
			os.Stdout.WriteString(b64Encode([]byte(err.Error())) + "\n")
			return err
		}
	default:
		in := os.Stdin
		if inFile := cmd.Flags().Arg(0); inFile != "" && inFile != "-" {
			f, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("failed to open input file %q: %v", inFile, err)
			}
			defer f.Close()
			in = f
		}
		return RunCli(cmd, tpm.TPM(), in, os.Stdout)
	}
	return nil
}

func pluginFlags(cmd *cobra.Command, opts *PluginOptions) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.BoolVarP(&pluginOptions.Convert, "convert", "y", false, "Convert identities to recipients.")
	flags.StringVarP(&pluginOptions.OutputFile, "output", "o", "", "Write the result to the file.")

	flags.BoolVarP(&pluginOptions.Generate, "generate", "g", false, "Generate a identity.")
	flags.BoolVarP(&pluginOptions.PIN, "pin", "p", false, "Include a pin with the key. Alternatively export AGE_TPM_PIN.")

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
