package plugin

import (
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

func mustPack(d []byte) []byte {
	packed, err := tpmutil.Pack(d)
	if err != nil {
		panic("couldn't pack")
	}
	return packed
}

var data = []struct {
	key string
	t   *Identity
}{
	{
		key: "AGE-PLUGIN-TPM-1QYQQQPMSWF5HVCT5V5QQVUR4VFKXJCC456Q6X",
		t: &Identity{
			Version: 1,
			Public:  mustPack([]byte("public")),
			Private: mustPack([]byte("private")),
		},
	},
}

func TestIdentityIdentityGeneration(t *testing.T) {
	for _, d := range data {
		k, err := EncodeIdentity(d.t)
		if err != nil {
			t.Fatalf("failed to encode key: %v", err)
		}
		if !reflect.DeepEqual(k, d.key) {
			t.Fatalf("no the same. Got %v expected %v", k, d.key)
		}
	}
}

func TestIdentityDecode(t *testing.T) {
	for _, d := range data {
		k, err := DecodeIdentity(d.key)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}
		if !reflect.DeepEqual(k, d.t) {
			t.Fatalf("no the same")
		}
	}
}
