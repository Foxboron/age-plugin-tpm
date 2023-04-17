package plugin

import (
	"crypto/rsa"
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

var cases = []struct {
	Handle    tpmutil.Handle
	PubKey    *rsa.PublicKey
	Recipient string
}{{
	Handle: 0x81000004,
	PubKey: &rsa.PublicKey{
		E: 65537,
		N: bigInt("23074459649211043193927873976369372930538737367631063235677833868354333787124787521069823694279163717451953709608433532984595648036527883092870568058184714843321589233137477139432342587953830510896568771215820290254539245240038437149623534718134669240829229520835777726788568244834190930188492978612809643533294346137807418656016081396190886171301968332135193256545553688640956497527597391712381340744680694990439605406788614708642918846426148021210755230575592910443549177037537223106399395479964021659966435160202776014590355916008880694369288004232455090425921750559378299332609853894828600326095583136272673818717"),
	},
	Recipient: "age1tpm1syqqqpqqqqqqqqqpqqqmdj83yzx8u6c8dzryazrg9x5sfek95tt2zdav9j0rz9s50wtaf04z909vfl32ep7u760m9k658y5lymstw23hwjnn8khkqeq7l0jdqczap03j908wj2luwpll992vnlsncryrhfgz5pk0ekflucy7ptsfxwqu59ujqynyd73yr6jqu86eyj8p7t7scwr8az9jhr87eu3wh3aljpd99uxkt7zsrp2m8g9h6eudf0xqhtljwjn4n0n229nu4gcnw8270spypz4ghagmszza9l5dnxf8twjkkvf2830vfv5kz26zqnq73rc0fases3p4dahtp5tu2hj7h40xpp2mxqy4lw5esfnrwjg70r6h73pse20vxwp00kta4npk9v7phrku6lck3akcg8juymrj7ku28fy96cmcvnv",
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
