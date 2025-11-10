package exchange

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
)

type CompleteExchangeAction struct {
	ecdhPrivateKey *ecdh.PrivateKey
}

func NewCompleteExchangeAction(ecdhPrivateKey *ecdh.PrivateKey) *CompleteExchangeAction {
	return &CompleteExchangeAction{
		ecdhPrivateKey: ecdhPrivateKey,
	}
}

type CompleteExchangeActionReturn struct {
	Message string `json:"message"`
}

func (c *CompleteExchangeAction) Execute(clientKey *string) (*CompleteExchangeActionReturn, error) {
	decoded, err := base64.StdEncoding.DecodeString(*clientKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decoded the base64 client key: %w", err)
	}

	probableKey, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key in pkix format: %w", err)
	}

	ecdsaPublicKey, ok := probableKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to interpret the parsed key as ecdsa public key")
	}

	publicKey, err := ecdsaPublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("unable to convert ecdsa public key to ecdh public key")
	}

	secret, err := c.ecdhPrivateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the secret: %w", err)
	}

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

	plainText := []byte("handshake complete")
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	return &CompleteExchangeActionReturn{
		Message: base64.StdEncoding.EncodeToString(cipherText),
	}, nil
}
