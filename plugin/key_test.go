package plugin

import (
	"reflect"
	"testing"
)

var data = []struct {
	key string
	t   *Identity
}{
	{
		key: "AGE-PLUGIN-TPM-1QXQSQQQPCTWLLV",
		t: &Identity{
			Version: 1,
			Handle:  0x81000001,
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
