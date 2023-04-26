package plugin

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

func bigInt(s string) *big.Int {
	ret := big.NewInt(0)
	ret.SetString(s, 10)
	return ret
}

func mustECDH(e *ecdsa.PublicKey) *ecdh.PublicKey {
	ret, _ := e.ECDH()
	return ret
}

var cases = []struct {
	Handle    tpmutil.Handle
	PubKey    *ecdh.PublicKey
	Recipient string
}{{
	Handle: 0x81000004,
	PubKey: mustECDH(
		&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     bigInt("89354244803538158909979995955747079783816134516555582017998279936143319776423"),
			Y:     bigInt("44449113766368004535934930895165275911452797542884597880018495457858036318074"),
		},
	),

	Recipient: "age1tpm1syqqqpqyckxttkp8xwu43ycm8xy9r39lxddaz3mr85zs3d3enql3a3xk8jnky32w3klcs29vj94445js7yq720qavvenpkpdq75ve7m2r4mr77stt6lyy",
}}

func TestDecodeRecipient(t *testing.T) {
	for _, c := range cases {
		handle, pubkey, err := DecodeRecipient(c.Recipient)
		if err != nil {
			t.Fatalf("failed decoding recipient: %v", err)
		}
		if c.Handle != handle {
			t.Fatalf("Failed to get handle. Expected %v got %v", c.Handle, handle)
		}
		if !reflect.DeepEqual(pubkey, c.PubKey) {
			t.Fatalf("Did not parse the correct key")
		}
	}
}

func TestEncodeRecipient(t *testing.T) {
	for _, c := range cases {
		s, err := EncodeRecipient(c.Handle, c.PubKey)
		if err != nil {
			t.Fatalf("failed encoding key: %v", err)
		}
		if !strings.EqualFold(s, c.Recipient) {
			t.Fatalf("did not the recipient back")
		}
	}
}
