package app

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func ParseEcdhP256PrivateKey(encodedPrivateKey string) (*ecdh.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 string: %w", err)
	}

	key, err := x509.ParseECPrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ec private key: %w", err)
	}

	privateKey, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("unable to extract ecdh private key: %w", err)
	}

	return privateKey, nil
}
