package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Return struct {
	Hash string
}

var errInternalServerError = errors.New("internal server error")

func main() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to load app config: %w", err))
	}
	rsaPrivateKey, err := ParseRsaPrivateKey(config.RawRsaPrivateKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse private key: %w", err))
	}

	router := gin.Default()
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(fmt.Errorf("unable to create logger: %w", err))
	}

	l := logger.Sugar()
	router.MaxMultipartMemory = 8 << 20

	router.POST("/file/hash", func(c *gin.Context) {
		h := c.Request.Header.Get("Content-Type")

		if h == "" {
			c.AbortWithError(http.StatusBadRequest, errors.New("Content-Type header is required"))
			return
		}

		if !strings.Contains(h, "multipart/form-data") {
			c.AbortWithError(http.StatusUnsupportedMediaType, errors.New("the correct content type for this request is multipart form data"))
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			l.Errorw("Error while opening the file", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
			return
		}

		openedFile, err := file.Open()
		if err != nil {
			l.Errorw("Error while opening the file", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
			return
		}
		defer openedFile.Close()

		hasher := crypto.SHA256.New()
		if _, err = io.Copy(hasher, openedFile); err != nil {
			l.Errorw("Error while reading file contents", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
			return
		}

		hashed := hasher.Sum(nil)
		hashString := hex.EncodeToString(hashed)

		ret := Return{
			Hash: hashString,
		}

		c.JSON(http.StatusOK, ret)
	})

	l.Info("Listening on 8080")
	router.Run()
}
