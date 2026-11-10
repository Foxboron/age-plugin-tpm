package plugin

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestParseHandle(t *testing.T) {
	cases := []struct {
		input   string
		want    tpm2.TPMIDHObject
		wantErr bool
	}{
		{"0x81000001", 0x81000001, false},
		{"0x81000002", 0x81000002, false},
		{"0x817fffff", 0x817fffff, false},
		{"2164260865", 0x81000001, false}, // 0x81000001 in decimal
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tc := range cases {
		got, err := ParseHandle(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseHandle(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseHandle(%q) = 0x%08x, want 0x%08x", tc.input, got, tc.want)
		}
	}
}

func TestSRKHandleEnv(t *testing.T) {
	SetSRKHandle(0x81000001)
	if GetSRKHandle() != 0x81000001 {
		t.Fatalf("expected default handle 0x81000001, got 0x%08x", GetSRKHandle())
	}

	os.Setenv("AGE_TPM_SRK_HANDLE", "0x81000005")
	defer os.Unsetenv("AGE_TPM_SRK_HANDLE")

	if GetSRKHandle() != 0x81000005 {
		t.Fatalf("expected env handle 0x81000005, got 0x%08x", GetSRKHandle())
	}
}

func TestPersistSRKAndAcquire(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm simulator: %v", err)
	}
	defer sim.Close()

	const targetHandle tpm2.TPMIDHObject = 0x81000002
	SetSRKHandle(targetHandle)
	defer SetSRKHandle(DefaultSRKHandle)

	identity, recipient, err := CreateIdentityWithOptions(sim, nil, true)
	if err != nil {
		t.Fatalf("failed creating identity with persist-srk: %v", err)
	}

	// Verify handle 0x81000002 exists in simulator
	pubRsp, err := tpm2.ReadPublic{ObjectHandle: targetHandle}.Execute(sim)
	if err != nil {
		t.Fatalf("failed reading public area of persisted handle 0x%08x: %v", targetHandle, err)
	}

	if !bytes.Equal(pubRsp.Name.Buffer, identity.SRKName.Buffer) {
		t.Fatalf("persisted SRK name does not match identity SRKName")
	}

	// Verify AcquireIdentitySRK returns the persistent handle directly
	srkAuthHandle, _, err := AcquireIdentitySRK(sim, identity)
	if err != nil {
		t.Fatalf("failed acquiring identity SRK: %v", err)
	}
	if srkAuthHandle.Handle.HandleValue() != uint32(targetHandle) {
		t.Fatalf("expected acquired handle 0x%08x, got 0x%08x", targetHandle, srkAuthHandle.Handle.HandleValue())
	}

	// Verify FlushHandle on persistent handle is a no-op and does not remove the handle
	FlushHandle(sim, srkAuthHandle)
	if _, err := (tpm2.ReadPublic{ObjectHandle: targetHandle}).Execute(sim); err != nil {
		t.Fatalf("handle was erroneously flushed: %v", err)
	}

	// Test encryption/decryption roundtrip
	fileKey := []byte("secret payload")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatalf("failed wrapping file key: %v", err)
	}

	identity.Callbacks(nil, sim, func() ([]byte, error) { return nil, nil })
	unwrapped, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("failed unwrapping file key: %v", err)
	}
	if !bytes.Equal(fileKey, unwrapped) {
		t.Fatalf("unwrapped key mismatch: got %v, want %v", unwrapped, fileKey)
	}
}

func TestAutoDiscoverPersistentSRK(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm simulator: %v", err)
	}
	defer sim.Close()

	const targetHandle tpm2.TPMIDHObject = 0x81000003

	// Persist SRK at 0x81000003
	srkHandle, _, err := PersistSRK(sim, targetHandle)
	if err != nil {
		t.Fatalf("failed persisting SRK at 0x%08x: %v", targetHandle, err)
	}

	// Create identity with SRKName set to the persisted SRK
	identity, recipient, err := CreateIdentity(sim, nil)
	if err != nil {
		t.Fatalf("failed creating identity: %v", err)
	}

	// Now set SRKHandle to a non-existent handle 0x81000009
	SetSRKHandle(0x81000009)
	defer SetSRKHandle(DefaultSRKHandle)

	// Update identity's SRKName to match the persisted SRK at 0x81000003
	identity.SRKName = &srkHandle.Name

	// AcquireIdentitySRK should fail on configured 0x81000009, then auto-discover 0x81000003
	discovered, _, err := AcquireIdentitySRK(sim, identity)
	if err != nil {
		t.Fatalf("auto-discovery of persistent SRK failed: %v", err)
	}
	if discovered.Handle.HandleValue() != uint32(targetHandle) {
		t.Fatalf("expected discovered handle 0x%08x, got 0x%08x", targetHandle, discovered.Handle.HandleValue())
	}

	// Also verify Unwrap works
	fileKey := []byte("payload for autodiscovery")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatalf("failed wrapping file key: %v", err)
	}

	identity.Callbacks(nil, sim, func() ([]byte, error) { return nil, nil })
	unwrapped, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("failed unwrapping file key: %v", err)
	}
	if !bytes.Equal(fileKey, unwrapped) {
		t.Fatalf("unwrapped key mismatch: got %v, want %v", unwrapped, fileKey)
	}
}
