package secrets

import (
	"testing"
)

func init() {
	SetKey("my super secret key")
}

func TestKey(t *testing.T) {
	plaintext := "some really really really long plaintext"
	ciphertext := encrypt(private_key, []byte(plaintext))
    if string(ciphertext) == plaintext {
        t.Error("plaintext not converted")
    }
	result := decrypt(private_key, ciphertext)
    if result != plaintext {
        t.Error("plaintext not recovered")
    }
}
