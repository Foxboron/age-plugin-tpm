package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type PluginOptions struct {
	AgePlugin         string
	Convert           bool
	Generate          bool
	Decrypt           bool
	Encrypt           bool
	OutputFile        string
	LogFile           string
	OldStyleRecipient bool
	PIN               bool
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
	fmt.Fprintf(os.Stderr, "%s ", prompt)
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
			f, err := os.OpenFile(pluginOptions.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
		}

		var rcp fmt.Stringer
		identity, recipient, err := plugin.CreateIdentity(tpm, pin)
		if err != nil {
			return err
		}
		rcp = recipient
		if pluginOptions.OldStyleRecipient {
			rcp = identity.TPMRecipient()
		}
		if err = plugin.MarshalIdentity(identity, rcp, out); err != nil {
			return err
		}
	case pluginOptions.Convert:
		if pluginOptions.OutputFile != "" && pluginOptions.OutputFile != "-" {
			f, err := os.OpenFile(pluginOptions.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
		}
		identity, err := plugin.ParseIdentity(in)
		if err != nil {
			return err
		}
		var recipient fmt.Stringer
		if pluginOptions.OldStyleRecipient {
			recipient = identity.TPMRecipient()
		} else {
			recipient, err = identity.Recipient()
			if err != nil {
				return err
			}
		}
		return plugin.MarshalRecipient(recipient, out)
	default:
		return cmd.Help()
	}
	return nil
}

func RunPlugin(cmd *cobra.Command, args []string) error {
	switch pluginOptions.AgePlugin {
	case "recipient-v1":
		plugin.Log.Println("Got recipient-v1")
		p, err := page.New("tpm")
		if err != nil {
			return err
		}
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			if p != nil {
				if err := p.DisplayMessage("The recipient was created with a previous version of age-plugin-tpm, please convert or create a new recipient."); err != nil {
					return nil, fmt.Errorf("failed displaying message: %v", err)
				}
			}
			return tag.NewClassicRecipient(data)
		})
		if exitCode := p.RecipientV1(); exitCode != 0 {
			return fmt.Errorf("age-plugin exited with code %d", exitCode)
		}
	case "identity-v1":
		tpm, err := plugin.NewTPM("")
		if err != nil {
			return err
		}
		defer tpm.Close()
		plugin.Log.Println("Got identity-v1")
		p, err := page.New("tpm")
		if err != nil {
			return err
		}
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			i, err := plugin.DecodeIdentity(page.EncodeIdentity("tpm", data))
			if err != nil {
				return nil, err
			}
			// Set callbacks for TPM and PIN access
			i.Callbacks(p, tpm,
				func() ([]byte, error) {
					var pin []byte
					if s := os.Getenv("AGE_TPM_PIN"); s != "" {
						pin = []byte(s)
					} else if s := os.Getenv("AGE_TPM_PINENTRY"); s != "" {
						pin, err = plugin.GetPinentry()
						if err != nil {
							return nil, err
						}
					} else {
						ps, err := p.RequestValue("Please enter the PIN for the key:", true)
						if err != nil {
							return nil, err
						}
						pin = []byte(ps)
					}
					return pin, nil
				},
			)
			return i, nil
		})
		os.Exit(p.Main())
	default:
		tpm, err := plugin.NewTPM("")
		if err != nil {
			return err
		}
		defer tpm.Close()
		in := os.Stdin
		if inFile := cmd.Flags().Arg(0); inFile != "" && inFile != "-" {
			f, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("failed to open input file %q: %v", inFile, err)
			}
			defer f.Close()
			in = f
		}
		return RunCli(cmd, tpm, in, os.Stdout)
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

	// Old style recipient
	flags.BoolVar(&pluginOptions.OldStyleRecipient, "tpm-recipient", false, "Use the old-style tpm recipient instead of the new p256tag recipient.")

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
