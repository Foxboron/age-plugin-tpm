package plugin

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
)

// Wrap swtpm and tpm into one device thing
type TPMDevice struct {
	isSwtpm bool
	tpm     io.ReadWriteCloser
	swtpm   *swtpm_test.Swtpm
}

func (t *TPMDevice) Close() {
	if t.isSwtpm {
		t.swtpm.Stop()
	}
	t.tpm.Close()
}

// Watch for a interrution signal
func (t *TPMDevice) Watch() {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT)
	go func() {
		<-sigch
		t.Close()
	}()
}

// Return the TPM rwc
func (t *TPMDevice) TPM() io.ReadWriteCloser {
	return t.tpm
}

// Setup a NewTPMDevice
func NewTPMDevice(tpmPath string, isSwtpm bool) (*TPMDevice, error) {
	var err error
	var swtpm *swtpm_test.Swtpm
	var tpm io.ReadWriteCloser

	if isSwtpm {
		// We setup the dir in-case it's a tmp thingie
		if _, err := os.Stat(tpmPath); errors.Is(err, os.ErrNotExist) {
			os.MkdirTemp(path.Dir(tpmPath), path.Base(tpmPath))
		}
		swtpm = swtpm_test.NewSwtpm(tpmPath)
		tpmPath, err = swtpm.Socket()
		if err != nil {
			return nil, err
		}
	}

	// If we don't pass a path to OpenTPM then we have the tpmrm0 and tpm0 fallbacks
	if tpmPath != "" {
		tpm, err = tpm2.OpenTPM(tpmPath)
	} else {
		tpm, err = tpm2.OpenTPM()
	}
	if err != nil {
		return nil, err
	}

	return &TPMDevice{
		isSwtpm: isSwtpm,
		tpm:     tpm,
		swtpm:   swtpm,
	}, nil
}

// Setup a new TPM device
func NewTPM(dir string) (*TPMDevice, error) {
	return NewTPMDevice(dir, false)
}

// Setup a new Software TPM
func NewSwTPM(dir string) (*TPMDevice, error) {
	return NewTPMDevice(dir, true)
}
