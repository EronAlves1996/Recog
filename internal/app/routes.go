package app

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"github.com/EronAlves1996/Recog/internal/app/exchange"
	"github.com/EronAlves1996/Recog/internal/pkg/cryptoutils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type SignMessageRequest struct {
	Message string `json:"message" binding:"required" validate:"min=1"`
}

type VerifyMessageSignatureRequest struct {
	SignMessageRequest
	Signature string `json:"signature" binding:"required" validate:"min=1"`
}

type ClientSecretRequest struct {
	ClientPublicKey string `json:"clientPublicKey" binding:"required" validate:"min=1"`
}

func registerRoutes(l *zap.SugaredLogger,
	rsaPair *cryptoutils.RsaPair,
	router *gin.Engine,
	action base.Action[base.Void, exchange.InitiateExchangeActionReturn],
	signMessageAction base.Action[io.Reader, []byte],
	completeExchangeAction base.Action[string, exchange.CompleteExchangeActionReturn]) {
	router.POST("/file/hash", hashFile(l))
	router.POST("/sign", gin.Bind(SignMessageRequest{}), signMessage(l, signMessageAction))
	router.POST("/verify", gin.Bind(VerifyMessageSignatureRequest{}), verifyMessageSignature(l, rsaPair))
	router.POST("/exchange/initiate", initiateExchange(l, action))
	router.POST("/exchange/complete", gin.Bind(ClientSecretRequest{}), completeExchange(l, completeExchangeAction))
}

func completeExchange(l *zap.SugaredLogger, completeExchangeAction base.Action[string, exchange.CompleteExchangeActionReturn]) gin.HandlerFunc {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*ClientSecretRequest)
		if !ok {
			abortFailedToDesserialize(l, c)
			return
		}

		ret, err := completeExchangeAction.Execute(&message.ClientPublicKey)
		if err != nil {
			l.Errorw("failed to execute action", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, err)

			return
		}

		c.JSON(http.StatusOK, ret)
	}
}

func initiateExchange(l *zap.SugaredLogger, action base.Action[base.Void, exchange.InitiateExchangeActionReturn]) gin.HandlerFunc {
	return func(c *gin.Context) {
		ret, err := action.Execute(nil)
		if err != nil {
			l.Errorw("failed to execute action", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
			return
		}

		c.JSON(http.StatusOK, ret)
	}
}

func verifyMessageSignature(l *zap.SugaredLogger, rsaPair *cryptoutils.RsaPair) func(c *gin.Context) {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*VerifyMessageSignatureRequest)
		if !ok {
			abortFailedToDesserialize(l, c)
			return
		}

		m, signature := message.Message, message.Signature
		decoded, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			l.Errorw("Failed to decode base64 signature", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
			return
		}

		hasher := crypto.SHA256.New()
		if _, err := hasher.Write([]byte(m)); err != nil {
			l.Errorw("Unable to hash the message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)

			return
		}
		hash := hasher.Sum(nil)

		if err := rsa.VerifyPSS(rsaPair.PublicKey, crypto.SHA256, hash, decoded, nil); err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false})
			return
		}

		c.JSON(http.StatusOK, gin.H{"valid": true})
	}
}

func signMessage(l *zap.SugaredLogger, action base.Action[io.Reader, []byte]) func(c *gin.Context) {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*SignMessageRequest)
		if !ok {
			abortFailedToDesserialize(l, c)
			return
		}

		buf := new(bytes.Buffer)
		buf.WriteString(message.Message)
		var reader io.Reader = buf

		signature, err := action.Execute(&reader)
		if err != nil {
			l.Errorw("Unable to generate signature", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errInternalServerError)

			return
		}

		c.JSON(http.StatusOK, gin.H{"signature": base64.StdEncoding.EncodeToString(*signature)})
	}
}

func abortFailedToDesserialize(l *zap.SugaredLogger, c *gin.Context) {
	l.Errorw("Unable to desserialize message request struct")
	c.AbortWithError(http.StatusInternalServerError, errInternalServerError)
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
