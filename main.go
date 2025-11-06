package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var errInternalServerError = errors.New("internal server error")

func main() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to load app config: %w", err))
	}
	rsaPair, err := ParseRsaPair(config.RawRsaPrivateKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse rsa pair: %w", err))
	}

	router := gin.Default()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to create logger: %w", err))
	}

	l := logger.Sugar()
	router.MaxMultipartMemory = 8 << 20
	registerRoutes(l, rsaPair, router)

	l.Info("Listening on 8080")
	router.Run()
}
