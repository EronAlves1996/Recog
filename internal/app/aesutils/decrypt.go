package aesutils

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

func Decrypt(secret []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to make aes cipher: %w", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to make gcm: %w", err))
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal(fmt.Errorf("ciphertext too short"))
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
