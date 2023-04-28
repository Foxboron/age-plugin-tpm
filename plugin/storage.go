package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/google/go-tpm/tpmutil"
)

var (
	config = "config.json"
)

func GetCacheDir() string {
	if cache, err := os.UserCacheDir(); err == nil {
		return path.Join(cache, "age-plugin-tpm")
	}
	// TODO: HOME and XDG_CACHE_HOME not available, wot?
	return ""
}

func GetConfigFile() string {
	return path.Join(GetCacheDir(), config)
}

type Identities map[tpmutil.Handle]*Identity

func GetSavedIdentities() (Identities, error) {
	keys := Identities{}
	b, err := os.ReadFile(GetConfigFile())
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(GetCacheDir(), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(GetConfigFile(), []byte(""), 0644); err != nil {
			return keys, err
		}
		return keys, nil
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func DeleteIdentity(i *Identity) error {
	identities, err := GetSavedIdentities()
	if err != nil {
		return err
	}
	delete(identities, tpmutil.Handle(i.Handle))
	b, err := json.Marshal(identities)
	if err != nil {
		return err
	}
	return os.WriteFile(GetConfigFile(), b, 0644)
}

func SaveIdentity(i *Identity) error {
	keys, err := GetSavedIdentities()
	if err != nil {
		return err
	}
	keys[tpmutil.Handle(i.Handle)] = i
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(GetConfigFile(), b, 0644)
}

func GetIdentity(handle tpmutil.Handle) (*Identity, error) {
	identities, err := GetSavedIdentities()
	if err != nil {
		return nil, err
	}
	k, ok := identities[handle]
	if !ok {
		return nil, fmt.Errorf("can't find key with handle")
	}
	return k, nil
}
