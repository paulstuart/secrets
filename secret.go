package secrets

// courtesy of http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

var (
    // to change without modifying the code: 
    // go build/test/install -ldflags "-X secrets.salty my-new-salt-string"
	salty  = "add salt to taste"
    private_key []byte
)

func SetKey(key_text string) {
	h := md5.New()
	io.WriteString(h, key_text)
	io.WriteString(h, salty)
	private_key = []byte(fmt.Sprintf("%x", h.Sum(nil)))
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func encryptString(text string) string {
    return encodeBase64(encrypt(private_key, []byte(text)))
}

func decryptString(text string) string {
    data := decodeBase64(text)
    return string(decrypt(private_key, data))
}

func encrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext
}

func decrypt(key, text []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return string(decodeBase64(string(text)))
}
