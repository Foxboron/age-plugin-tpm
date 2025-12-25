package main

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age-plugin-tpm": func() {
			main()
		},
	})
}

func TestPlugin(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars, "AGE_TPM_SWTPM=1")
			e.Vars = append(e.Vars, "_AGE_TPM_SIMULATOR=1")
			return nil
		},
	})
}
