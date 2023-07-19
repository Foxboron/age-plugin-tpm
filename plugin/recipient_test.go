package plugin

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"strings"
	"testing"
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
	pubKey    *Recipient
	recipient string
}{{
	pubKey: NewRecipient(mustECDH(
		&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     bigInt("89354244803538158909979995955747079783816134516555582017998279936143319776423"),
			Y:     bigInt("44449113766368004535934930895165275911452797542884597880018495457858036318074"),
		},
	)),

	recipient: "age1tpm1qtzcedwcyuemjkynrvucs5wyhue4h528vv7s2z9k8xvr78ky6c72wff0tz2",
}}

func TestDecodeRecipient(t *testing.T) {
	for _, c := range cases {
		pubkey, err := DecodeRecipient(c.recipient)
		if err != nil {
			t.Fatalf("failed decoding recipient: %v", err)
		}
		if !reflect.DeepEqual(pubkey, c.pubKey.Pubkey) {
			t.Fatalf("Did not parse the correct key")
		}
	}
}

func TestEncodeRecipient(t *testing.T) {
	for _, c := range cases {
		s := EncodeRecipient(c.pubKey)
		if !strings.EqualFold(s, c.recipient) {
			t.Fatalf("did not get the recipient back")
		}
	}
}
