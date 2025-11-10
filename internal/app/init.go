package app

import (
	"errors"
	"fmt"
	"log"

	"github.com/EronAlves1996/Recog/internal/app/exchange"
	"github.com/EronAlves1996/Recog/internal/app/signature"
	"github.com/EronAlves1996/Recog/internal/pkg/cryptoutils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var errInternalServerError = errors.New("internal server error")

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

	router := gin.Default()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to create logger: %w", err))
	}

	l := logger.Sugar()
	router.MaxMultipartMemory = 8 << 20

	signMessageAction := signature.NewSignBytesRsaAction(rsaPair, l)
	initiateExchangeAction := exchange.NewInitiateExchangeAction(l, ecdhPrivateKey, signMessageAction)

	registerRoutes(l, rsaPair, router, initiateExchangeAction, signMessageAction)

	l.Info("Listening on 8080")
	router.Run()
}
