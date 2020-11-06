package util

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// GetSecretValue returns the value of the Secret from its source
func GetSecretValue(source *options.SecretSource) ([]byte, error) {
	switch {
	case len(source.Value) > 0 && source.FromEnv == "" && source.FromFile == "":
		value := make([]byte, base64.StdEncoding.DecodedLen(len(source.Value)))
		decoded, err := base64.StdEncoding.Decode(value, source.Value)
		return value[:decoded], err
	case len(source.Value) == 0 && source.FromEnv != "" && source.FromFile == "":
		return []byte(os.Getenv(source.FromEnv)), nil
	case len(source.Value) == 0 && source.FromEnv == "" && source.FromFile != "":
		return ioutil.ReadFile(source.FromFile)
	default:
		return nil, errors.New("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile")
	}
}
