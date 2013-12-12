package secrets

import (
	"testing"
)

var (
	public_file  = "sample.cfg"
    private_file = "encoded.cfg"
)

func TestConfig(t *testing.T) {
	config, err := ConfigLoad(public_file)
    if err != nil {
        t.Error(err.Error())
    }
    if len(config.Filer) == 0 {
        t.Error("no config entries found")
    }
}

func TestSecretConfig(t *testing.T) {
	config, err := ConfigLoad(public_file)
    if err != nil {
        t.Error(err.Error())
    }
    private := config.Copy()
    private.Private()
    if ConfigCompare(config,private) {
        t.Error("failed to make private config")
    }
    private.Public()
    if ! ConfigCompare(config,private) {
        t.Error("failed to make private config")
    }
}

func TestSaveSecretConfig(t *testing.T) {
	config, err := ConfigLoad(public_file)
    if err != nil {
        t.Error(err.Error())
    }
    config.Private()
    config.Save(private_file)
}

func TestLoad(t *testing.T) {
	config, err := ConfigLoad(private_file)
    if err != nil {
        t.Error(err.Error())
    }
    config.Public()
}
