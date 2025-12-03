package app

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"github.com/EronAlves1996/Recog/internal/app/exchange"
	"github.com/EronAlves1996/Recog/internal/app/hash"
	"github.com/EronAlves1996/Recog/internal/app/httputils"
	"github.com/EronAlves1996/Recog/internal/pkg/cryptoutils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type SignMessageRequest struct {
	Message string `json:"message" binding:"required" validate:"min=1"`
}

type RawJSONObject []byte

func (r *RawJSONObject) UnmarshalJSON(data []byte) error {
	*r = data
	return nil
}

type VerifyMessageSignatureRequest struct {
	Message   RawJSONObject `json:"message" binding:"required"`
	Signature string        `json:"signature" binding:"required" validate:"min=1"`
}

type ClientSecretRequest struct {
	ClientPublicKey string `json:"clientPublicKey" binding:"required" validate:"min=1"`
}

type ResumeSessionRequest struct {
	SessionTicket string `json:"sessionTicket" binding:"required"`
}

type CertificateRequest struct {
	Certificate string `json:"certificate" binding:"required"`
}

type ApplicationContext struct {
	logger                      *zap.SugaredLogger
	rsaPair                     *cryptoutils.RsaPair
	router                      *gin.Engine
	action                      base.Action[base.Void, exchange.InitiateExchangeActionReturn]
	signMessageAction           base.Action[io.Reader, []byte]
	completeExchangeAction      base.Action[string, exchange.CompleteExchangeActionReturn]
	retrieveSessionTicketAction base.Action[string, string]
	resumeSessionAction         base.Action[string, base.Void]
	aesSessionTicketKey         []byte
	validateCertificateAction   base.Action[[]byte, bool]
}

func registerRoutes(appContext ApplicationContext) {
	appContext.router.POST("/file/hash", hashFile(appContext.logger))
	appContext.router.POST("/sign", gin.Bind(SignMessageRequest{}), signMessage(appContext.logger, appContext.signMessageAction))
	appContext.router.POST("/verify", gin.Bind(VerifyMessageSignatureRequest{}), verifyMessageSignature(appContext.logger, appContext.rsaPair))
	appContext.router.POST("/exchange/initiate", initiateExchange(appContext.logger, appContext.action))
	appContext.router.POST("/exchange/complete", gin.Bind(ClientSecretRequest{}), completeExchange(appContext.logger, appContext.completeExchangeAction))
	appContext.router.GET("/session/ticket/:id", retrieveSessionTicket(appContext.logger, appContext.retrieveSessionTicketAction))
	appContext.router.POST("/session/resume", gin.Bind(ResumeSessionRequest{}), resumeSession(appContext.logger, appContext.resumeSessionAction))
	appContext.router.POST("/certificate/validate",
		decryptBodyMiddleware(appContext.aesSessionTicketKey),
		gin.Bind(CertificateRequest{}),
		validateCertificate(appContext.logger, appContext.validateCertificateAction))
}

func validateCertificate(sugaredLogger *zap.SugaredLogger, validateCertificateAction base.Action[[]byte, bool]) gin.HandlerFunc {
	return func(c *gin.Context) {
		certificate, ok := c.MustGet(gin.BindKey).(*CertificateRequest)
		if !ok {
			httputils.AbortFailedToDesserialize(sugaredLogger, c)
			return
		}

		binaryCertificate, err := base64.StdEncoding.DecodeString(certificate.Certificate)
		if err != nil {
			sugaredLogger.Errorw("failed to decode certificate", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		valid, err := validateCertificateAction.Execute(c.Request.Context(), &binaryCertificate)
		if err != nil {
			sugaredLogger.Errorw("failed to validate certificate", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"valid": *valid,
		})
	}
}

func resumeSession(l *zap.SugaredLogger, resumeSessionAction base.Action[string, base.Void]) gin.HandlerFunc {
	return func(c *gin.Context) {
		ticket, ok := c.MustGet(gin.BindKey).(*ResumeSessionRequest)
		if !ok {
			httputils.AbortFailedToDesserialize(l, c)
			return
		}

		if _, err := resumeSessionAction.Execute(c.Request.Context(), &ticket.SessionTicket); err != nil {
			c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("unable to resume session"))
			return
		}
	}

}

func retrieveSessionTicket(l *zap.SugaredLogger, retrieveSessionTicketAction base.Action[string, string]) gin.HandlerFunc {
	return func(c *gin.Context) {
		stringId := c.Param("id")

		ticket, err := retrieveSessionTicketAction.Execute(c.Request.Context(), &stringId)
		if err != nil {
			l.Errorw("failed to retrieve ticket", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to retrieve ticket: %w", err))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ticket": ticket,
		})
	}
}

func completeExchange(l *zap.SugaredLogger, completeExchangeAction base.Action[string, exchange.CompleteExchangeActionReturn]) gin.HandlerFunc {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*ClientSecretRequest)
		if !ok {
			httputils.AbortFailedToDesserialize(l, c)
			return
		}

		ret, err := completeExchangeAction.Execute(c.Request.Context(), &message.ClientPublicKey)
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
		ret, err := action.Execute(c.Request.Context(), nil)
		if err != nil {
			l.Errorw("failed to execute action", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		c.JSON(http.StatusOK, ret)
	}
}

func verifyMessageSignature(l *zap.SugaredLogger, rsaPair *cryptoutils.RsaPair) func(c *gin.Context) {
	return func(c *gin.Context) {
		message, ok := c.MustGet(gin.BindKey).(*VerifyMessageSignatureRequest)
		if !ok {
			httputils.AbortFailedToDesserialize(l, c)
			return
		}

		m, signature := message.Message, message.Signature
		decoded, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			l.Errorw("Failed to decode base64 signature", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		hasher := crypto.SHA256.New()
		if _, err := hasher.Write([]byte(m)); err != nil {
			l.Errorw("Unable to hash the message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)

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
			httputils.AbortFailedToDesserialize(l, c)
			return
		}

		marshaled, err := json.Marshal(message.Message)
		if err != nil {
			l.Errorw("failed to marshal the message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)

			return
		}

		buf := new(bytes.Buffer)
		buf.Write(marshaled)
		var reader io.Reader = buf

		signature, err := action.Execute(c.Request.Context(), &reader)
		if err != nil {
			l.Errorw("Unable to generate signature", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)

			return
		}

		c.JSON(http.StatusOK, gin.H{"signature": base64.StdEncoding.EncodeToString(*signature)})
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
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		openedFile, err := file.Open()
		if err != nil {
			l.Errorw("Error while opening the file", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}
		defer openedFile.Close()

		hasher := crypto.SHA256.New()
		hashString, err := hash.Hash(l, hasher, openedFile)
		if err != nil {
			l.Errorw("Error hashing file contents", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		c.JSON(http.StatusOK, gin.H{"hash": hashString})
	}
}
