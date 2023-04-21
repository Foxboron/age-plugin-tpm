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

type Keys map[tpmutil.Handle]*Key

func GetSavedKeys() (Keys, error) {
	keys := Keys{}
	b, err := os.ReadFile(GetConfigFile())
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(GetCacheDir(), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(config, []byte(""), 0644); err != nil {
			return keys, err
		}
		return keys, nil
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func DeleteKey(k *Key) error {
	keys, err := GetSavedKeys()
	if err != nil {
		return err
	}
	delete(keys, tpmutil.Handle(k.Handle))
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(GetConfigFile(), b, 0644)
}

func SaveKey(k *Key) error {
	keys, err := GetSavedKeys()
	if err != nil {
		return err
	}
	keys[tpmutil.Handle(k.Handle)] = k
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(GetConfigFile(), b, 0644)
}

func GetKey(handle tpmutil.Handle) (*Key, error) {
	keys, err := GetSavedKeys()
	if err != nil {
		return nil, err
	}
	k, ok := keys[handle]
	if !ok {
		return nil, fmt.Errorf("can't find key with handle")
	}
	return k, nil
}
