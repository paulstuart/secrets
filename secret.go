package secrets

// courtesy of http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
)

const tokenLayout = "2006-01-02@15:04:05"

var (
	ErrIncomplete = fmt.Errorf("missing data")
	ErrChecksum   = fmt.Errorf("checksum does not match")
	ErrCipherText = fmt.Errorf("ciphertext too short")
	ErrKeyExpired = fmt.Errorf("key expired")
	ErrBadSecret  = fmt.Errorf("bad secret")
)

var (
	active = make(map[string]KeySpan)
)

// Time period the cert is valid for
type KeySpan struct {
	From, To time.Time
}

func (k KeySpan) String() string {
	return fmt.Sprintf("FROM:%s TO:%s\n", k.From.Format(tokenLayout), k.To.Format(tokenLayout))
}

// create a "certificate hash) that includes the time it is valid for
func NewCert(from, to time.Time) (string, error) {
	k, err := KeyGen()
	if err != nil {
		return "", err
	}
	s, err := EncryptString(strings.Join([]string{
		from.Format(tokenLayout),
		to.Format(tokenLayout),
		k,
	}, " "))
	if err != nil {
		return "", err
	}
	return s + fmt.Sprintf("%X", crc32.ChecksumIEEE([]byte(s))), nil
}

func Validate(cert string) (*KeySpan, error) {
	const cLen = 208
	if len(cert) < cLen {
		return nil, ErrIncomplete
	}
	chksum := fmt.Sprintf("%X", crc32.ChecksumIEEE([]byte(cert[:cLen])))
	if chksum != cert[cLen:] {
		return nil, ErrChecksum
	}
	secret, err := DecryptString(cert[:cLen])
	if err != nil {
		return nil, err
	}
	if len(secret) < 40 {
		return nil, ErrBadSecret
	}
	til := len(tokenLayout)
	from, err := time.Parse(tokenLayout, secret[:til])
	if err != nil {
		return nil, err
	}
	til++
	to, err := time.Parse(tokenLayout, secret[til:til+len(tokenLayout)])
	if err != nil {
		return nil, err
	}

	return &KeySpan{from, to}, nil
}

var (
	// to change without modifying the code:
	// go build/test/install -ldflags "-X secrets.salty my-new-salt-string"
	salty       = "add salt to taste"
	private_key []byte
)

func SetKey(key_text string) {
	h := md5.New()
	io.WriteString(h, key_text)
	io.WriteString(h, salty)
	private_key = []byte(fmt.Sprintf("%x", h.Sum(nil)))
}

func KeyGen() (string, error) {
	data := make([]byte, 10)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func EncryptString(text string) (string, error) {
	c, err := Encrypt(private_key, []byte(text))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(c), nil
}

func DecryptString(text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	d, err := Decrypt(private_key, data)
	return string(d), err
}

func Encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ciphertext, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func Decrypt(key, text []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(text) < aes.BlockSize {
		return "", ErrCipherText
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	s, err := base64.StdEncoding.DecodeString(string(text))
	return string(s), err
}
