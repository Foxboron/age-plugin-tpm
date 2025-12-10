package plugin

import (
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func mustPublic(data []byte) tpm2.TPM2BPublic {
	return tpm2.BytesAs2B[tpm2.TPMTPublic](data)
}

func mustPrivate(data []byte) tpm2.TPM2BPrivate {
	return tpm2.TPM2BPrivate{
		Buffer: data,
	}
}

func mustSRK(data []byte) *tpm2.TPM2BName {
	return &tpm2.TPM2BName{
		Buffer: data,
	}
}

var data = []struct {
	key string
	t   *Identity
}{
	{
		key: "AGE-PLUGIN-TPM-1QYQQQPNSW43XC6TRQQRHQUNFWESHGEGN0E0FM",
		t: &Identity{
			Version: 1,
			Public:  mustPublic([]byte("public")),
			Private: mustPrivate([]byte("private")),
		},
	},
	{
		key: "AGE-PLUGIN-TPM-1QYQSQPNSW43XC6TRQQRHQUNFWESHGEGWKR32R",
		t: &Identity{
			Version: 1,
			PIN:     HasPIN,
			Public:  mustPublic([]byte("public")),
			Private: mustPrivate([]byte("private")),
		},
	},
	{
		key: "AGE-PLUGIN-TPM-1QGQQQPNSW43XC6TRQQRHQUNFWESHGEGQQDEHY6CUT4TFU",
		t: &Identity{
			Version: 2,
			Public:  mustPublic([]byte("public")),
			Private: mustPrivate([]byte("private")),
			SRKName: mustSRK([]byte("srk")),
		},
	},
	{
		key: "AGE-PLUGIN-TPM-1QGQSQPNSW43XC6TRQQRHQUNFWESHGEGQQDEHY6CHRM9KS",
		t: &Identity{
			Version: 2,
			PIN:     HasPIN,
			Public:  mustPublic([]byte("public")),
			Private: mustPrivate([]byte("private")),
			SRKName: mustSRK([]byte("srk")),
		},
	},
}

func TestIdentityIdentityGeneration(t *testing.T) {
	for _, d := range data {
		k := d.t.String()
		if !reflect.DeepEqual(k, d.key) {
			t.Fatalf("no the same. Got %v expected %v", k, d.key)
		}
	}
}

// func TestIdentityDecode(t *testing.T) {
// 	for _, d := range data {
// 		k, err := DecodeIdentity(d.key)
// 		if err != nil {
// 			t.Fatalf("failed to decode key: %v", err)
// 		}
// 		if !reflect.DeepEqual(k, d.t) {
// 			t.Fatalf("no the same")
// 		}
// 	}
// }

func TestIdentityCreateEncodeDecode(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()

	SetLogger(io.Discard)
	identity, _, err1 := CreateIdentity(tpm, nil)
	identity.Callbacks(nil, tpm, func() ([]byte, error) { return nil, nil })

	k := identity.String()

	identity2, err2 := DecodeIdentity(k)

	if err = errors.Join(err1, err2); err != nil {
		t.Fatalf("failed test: %v", err)
	}

	if identity2.String() != k {
		t.Fatalf("failed to parse identityes")
	}
}
