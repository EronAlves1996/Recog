package app

import (
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/joho/godotenv"
)

type RedisConfig struct {
	RedisUrl      string
	RedisDb       int
	RedisPassword string
}

type Config struct {
	RawRsaPrivateKey    string
	EcP256PrivateKey    string
	AesSessionTicketKey string
	RedisConfig         RedisConfig
	BcryptCost          int
}

func LoadConfig() (*Config, error) {
	p, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := godotenv.Load(path.Join(p, ".env")); err != nil {
		return nil, err
	}

	redisDb, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, fmt.Errorf("error while recovering redis config: %w", err)
	}

	bcryptCost, err := strconv.Atoi(os.Getenv("BCRYPT_COST"))
	if err != nil {
		return nil, fmt.Errorf("failed to recover bcrypt cost: %w", err)
	}

	c := Config{
		RawRsaPrivateKey:    os.Getenv("RSA_PRIVATE_KEY"),
		EcP256PrivateKey:    os.Getenv("EC_P256_PRIVATE_KEY"),
		AesSessionTicketKey: os.Getenv("AES_SESSIONTICKETS_KEY"),
		BcryptCost:          bcryptCost,
		RedisConfig: RedisConfig{
			RedisUrl:      os.Getenv("REDIS_URL"),
			RedisDb:       redisDb,
			RedisPassword: os.Getenv("REDIS_PASSWORD"),
		},
	}

	return &c, nil
}
