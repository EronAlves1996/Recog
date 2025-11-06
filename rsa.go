package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

type RsaPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func ParseRsaPair(encodedPublicKey string) (*RsaPair, error) {
	privateKey, err := ParseRsaPrivateKey(encodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse rsa private key: %w", err)
	}
	r := &RsaPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}

	return r, nil
}

func ParseRsaPrivateKey(encodedPublicKey string) (*rsa.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 string: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to decode private key")
	}

	return privateKey, nil
}
