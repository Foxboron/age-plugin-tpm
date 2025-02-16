package plugin

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"

	swtpm_test "github.com/foxboron/swtpm_test"
	sim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// Wrap swtpm and tpm into one device thing
type TPMDevice struct {
	isSwtpm bool
	tpm     transport.TPMCloser
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
func (t *TPMDevice) TPM() transport.TPMCloser {
	return t.tpm
}

var (
	once sync.Once
	s    transport.TPMCloser
)

// TPM represents a connection to a TPM simulator.
type TPMCloser struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPMCloser) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPMCloser) Close() error {
	return t.transport.Close()
}

func GetFixedSim() (transport.TPMCloser, error) {
	var ss *sim.Simulator
	var err error
	once.Do(func() {
		ss, err = sim.GetWithFixedSeedInsecure(123456)
		s = &TPMCloser{ss}
	})
	return s, err
}

// Setup a NewTPMDevice
func NewTPMDevice(tpmPath string, isSwtpm bool) (*TPMDevice, error) {
	var err error
	var swtpm *swtpm_test.Swtpm
	var tpm transport.TPMCloser

	if isSwtpm {
		if os.Getenv("_AGE_TPM_SIMULATOR") != "" {
			tpm, err = GetFixedSim()
			if err != nil {
				return nil, err
			}
			return &TPMDevice{
				tpm: tpm,
			}, nil
		}
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
		tpm, err = transport.OpenTPM(tpmPath)
	} else {
		tpm, err = transport.OpenTPM()
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

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func FlushHandle(tpm transport.TPM, h handle) {
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}
