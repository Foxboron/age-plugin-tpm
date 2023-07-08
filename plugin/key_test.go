package plugin

import (
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func mustPack(d []byte) []byte {
	packed, err := tpmutil.Pack(d)
	if err != nil {
		panic("couldn't pack")
	}
	return packed
}

func mustPublic(data []byte) tpm2.TPM2BPublic {
	tpmdata := tpm2.TPM2BData{
		Buffer: data,
	}
	b := tpm2.Marshal(tpmdata)
	ret, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	if err != nil {
		panic("cant marshal")
	}
	return *ret
}

func mustPrivate(data []byte) tpm2.TPM2BPrivate {
	tpmdata := tpm2.TPM2BData{
		Buffer: data,
	}
	b := tpm2.Marshal(tpmdata)
	ret, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b)
	if err != nil {
		panic("cant marshal")
	}
	return *ret
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
