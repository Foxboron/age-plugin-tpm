package plugin

import (
	"errors"

	"github.com/twpayne/go-pinentry"
)

var (
	ErrPinentryCancelled = errors.New("cancelled pinentry")
)

func GetPinentry() ([]byte, error) {
	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithDesc("Enter PIN for age identity"),
		pinentry.WithGPGTTY(),
		pinentry.WithPrompt("PIN:"),
		pinentry.WithTitle("age-plugin-tpm PIN entry"),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	switch pin, fromCache, err := client.GetPIN(); {
	case pinentry.IsCancelled(err):
		return nil, ErrPinentryCancelled
	case err != nil:
		return nil, err
	case fromCache:
		return []byte(pin), nil
	default:
		return []byte(pin), nil
	}
}
