package aesutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func Encrypt(secret []byte, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to generate gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to initialize the intialization vector: %w", err)
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}
