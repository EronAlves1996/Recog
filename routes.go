package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type SignMessageRequest struct {
	Message string `json:"message" binding:"required" validate:"min=1"`
}

func registerRoutes(l *zap.SugaredLogger, rsaPair *RsaPair, router *gin.Engine) {
	router.POST("/file/hash", hashFile(l))
	router.POST("/sign", gin.Bind(SignMessageRequest{}), signMessage(l, rsaPair))
}

func signMessage(l *zap.SugaredLogger, rsaPair *RsaPair) func(c *gin.Context) {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*SignMessageRequest)
		if !ok {
			l.Errorw("Unable to desserialize message request struct")
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)

			return
		}

		sha256 := crypto.SHA256.New()
		if _, err := sha256.Write([]byte(message.Message)); err != nil {
			l.Errorw("Unable to hash the message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)

			return
		}

		digest := sha256.Sum(nil)

		signature, err := rsa.SignPSS(rand.Reader, rsaPair.privateKey, crypto.SHA256, digest, nil)
		if err != nil {
			l.Errorw("Unable to sign the hash", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)

			return
		}

		c.JSON(http.StatusOK, gin.H{"signature": base64.StdEncoding.EncodeToString(signature)})
	}
}

func hashFile(l *zap.SugaredLogger) func(c *gin.Context) {
	return func(c *gin.Context) {
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

		c.JSON(http.StatusOK, gin.H{"hash": hashString})
	}
}
