package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

func ParseRsaPrivateKey(encodedPublicKey string) (*rsa.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, err
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to decode private key")
	}

	return privateKey, nil
}
