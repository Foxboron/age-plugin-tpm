package script_tests

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

func ScriptsWithPath(t *testing.T, path string) {
	tmp := t.TempDir()
	c := exec.Command("go", "build", "-buildmode=pie", "-o", tmp, "../cmd/...")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	testscript.Run(t, testscript.Params{
		Deadline: time.Now().Add(5 * time.Second),
		Setup: func(e *testscript.Env) error {
			e.Setenv("PATH", tmp+string(filepath.ListSeparator)+e.Getenv("PATH"))
			e.Vars = append(e.Vars, "AGE_TPM_SWTMP=1")
			e.Vars = append(e.Vars, "_AGE_TPM_SIMULATOR=1")
			return nil
		},
		Dir: path,
	})
}

func TestAgent(t *testing.T) {
	ScriptsWithPath(t, "age-plugin-tpm/testdata/script")
}
