package main

import (
	"os"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age-plugin-tpm": func() {
			main()
		},
		"age-plugin-tag": func() {
			p, _ := plugin.New("tag")
			p.HandleRecipient(func(data []byte) (age.Recipient, error) {
				// TODO: Remove
				// Backwards compat waiting for new release
				return tag.NewClassicRecipient(data)
			})
			p.HandleIdentity(func(data []byte) (age.Identity, error) {
				// TODO: We should not touch this
				return nil, nil
			})
			os.Exit(p.Main())
		},
	})
}

func TestPlugin(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars, "_AGE_TPM_SIMULATOR=1")
			return nil
		},
	})
}
