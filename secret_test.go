package secrets

import (
	"testing"
)

func init() {
	SetKey("my super secret key")
}

func TestKey(t *testing.T) {
	plaintext := "some really really really long plaintext"
	ciphertext, err := encrypt(private_key, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}
	if string(ciphertext) == plaintext {
		t.Error("plaintext not converted")
	}
	result, err := decrypt(private_key, ciphertext)
	if err != nil {
		t.Error(err)
	}
	if result != plaintext {
		t.Error("plaintext not recovered")
	}
}
