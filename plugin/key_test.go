package plugin

import (
	"reflect"
	"testing"
)

var data = []struct {
	key string
	t   *Key
}{
	{
		key: "AGE-PLUGIN-TPM1QXQSQQQPHUH2ES",
		t: &Key{
			Version: 1,
			Handle:  0x81000001,
		},
	},
}

func TestKeyGeneration(t *testing.T) {
	for _, d := range data {
		k, err := EncodeKey(d.t)
		if err != nil {
			t.Fatalf("failed to encode key: %v", err)
		}
		if !reflect.DeepEqual(k, d.key) {
			t.Fatalf("no the same. Got %v expected %v", k, d.key)
		}
	}
}

func TestKeyDecode(t *testing.T) {
	for _, d := range data {
		k, err := DecodeKey(d.key)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}
		if !reflect.DeepEqual(k, d.t) {
			t.Fatalf("no the same")
		}
	}
}
