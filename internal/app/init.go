package app

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/EronAlves1996/Recog/internal/app/certificate"
	"github.com/EronAlves1996/Recog/internal/app/exchange"
	"github.com/EronAlves1996/Recog/internal/app/message"
	"github.com/EronAlves1996/Recog/internal/app/session"
	"github.com/EronAlves1996/Recog/internal/app/signature"
	"github.com/EronAlves1996/Recog/internal/pkg/cryptoutils"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func createRedisClient(config *Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     config.RedisConfig.RedisUrl,
		Password: config.RedisConfig.RedisPassword,
		DB:       config.RedisConfig.RedisDb,
	})
}

func parseAesSessionTicketKey(config *Config) ([]byte, error) {
	aesKey := config.AesSessionTicketKey
	return base64.StdEncoding.DecodeString(aesKey)
}

func Run() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to load app config: %w", err))
	}

	rsaPair, err := cryptoutils.ParseRsaPair(config.RawRsaPrivateKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse rsa pair: %w", err))
	}

	ecdhPrivateKey, err := ParseEcdhP256PrivateKey(config.EcP256PrivateKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse ecdh private key: %w", err))
	}

	redisClient := createRedisClient(config)
	aesSessionTicketKey, err := parseAesSessionTicketKey(config)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse aes session ticket key: %w", err))
	}

	router := gin.Default()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to create logger: %w", err))
	}

	l := logger.Sugar()
	router.MaxMultipartMemory = 8 << 20

	signMessageAction := signature.NewSignBytesRsaAction(rsaPair, l)
	initiateExchangeAction := exchange.NewInitiateExchangeAction(l, ecdhPrivateKey, signMessageAction)
	completeExchangeAction := exchange.NewCompleteExchangeAction(ecdhPrivateKey, redisClient, aesSessionTicketKey)
	retrieveSessionTicketAction := session.NewRetrieveTicketAction(*redisClient)
	resumeSessionAction := session.NewResumeSessionAction(aesSessionTicketKey)

	message.RegisterRoutes(router, l, l, redisClient, aesSessionTicketKey)
	registerRoutes(ApplicationContext{
		logger:                      l,
		rsaPair:                     rsaPair,
		router:                      router,
		action:                      initiateExchangeAction,
		signMessageAction:           signMessageAction,
		completeExchangeAction:      completeExchangeAction,
		retrieveSessionTicketAction: retrieveSessionTicketAction,
		resumeSessionAction:         resumeSessionAction,
		aesSessionTicketKey:         aesSessionTicketKey,
		validateCertificateAction:   certificate.NewValidateCertificateAction(),
	})

	l.Info("Listening on 8080")
	router.Run()
}
