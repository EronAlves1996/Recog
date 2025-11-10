package app

import (
	"os"
	"path"

	"github.com/joho/godotenv"
)

type Config struct {
	RawRsaPrivateKey string
}

func LoadConfig() (*Config, error) {
	p, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := godotenv.Load(path.Join(p, ".env")); err != nil {
		return nil, err
	}

	c := Config{
		RawRsaPrivateKey: os.Getenv("RSA_PRIVATE_KEY"),
	}

	return &c, nil
}
