package plugin

import (
	"crypto/ecdh"
	"io"
	"os"
	"sync"

	sim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpmutil"
)

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
func NewTPM(tpmPath string) (transport.TPMCloser, error) {
	if os.Getenv("_AGE_TPM_SIMULATOR") != "" {
		return GetFixedSim()
	}

	// If we don't pass a path to OpenTPM then we have the tpmrm0 and tpm0 fallbacks
	if tpmPath != "" {
		return linuxtpm.Open(tpmPath)
	}
	return linuxtpm.Open("/dev/tpmrm0")
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

func PublicToECDH(b tpm2.TPM2BPublic) (*ecdh.PublicKey, error) {
	pub, err := b.Contents()
	if err != nil {
		return nil, err
	}

	parameters, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}

	eccdeets, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	return tpm2.ECDHPub(parameters, eccdeets)
}
