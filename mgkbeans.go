package mgkbeans

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type Beans struct {
	Key []byte
}

func (b Beans) Spill(enc, iv string) ([]byte, error) {
	key := sha256.Sum256(b.Key)
	block, err := aes.NewCipher([]byte(key[:len(key)]))
	if err != nil {
		return nil, err
	}

	vector, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	encrypted, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}

	if len(encrypted) < aes.BlockSize {
		return nil, errors.New("encrypted text is too small")
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("encrypted text is not multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, vector)
	mode.CryptBlocks(encrypted, encrypted)

	return PKCS5UnPadding(encrypted), nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:length-unpadding]
}
