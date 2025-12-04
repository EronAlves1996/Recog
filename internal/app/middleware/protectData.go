package middleware

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/EronAlves1996/Recog/internal/app/aesutils"
	"github.com/EronAlves1996/Recog/internal/app/ticket"
	"github.com/gin-gonic/gin"
)

type encryptorBodyWriter struct {
	gin.ResponseWriter
	aesKey []byte
}

func (w encryptorBodyWriter) Write(b []byte) (int, error) {
	encrypted, err := aesutils.Encrypt(w.aesKey, b)

	if err != nil {
		return 0, err
	}

	return w.ResponseWriter.Write(encrypted)
}

func ProtectDataMiddleware(aesSessionTicketKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionTicket := c.Request.Header.Get("X-Session-Ticket")
		if sessionTicket == "" {
			c.AbortWithError(http.StatusUnauthorized, errors.New("no session ticket found"))
			return
		}

		decodedEncryptedSessionTicket, err := base64.StdEncoding.DecodeString(sessionTicket)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, errors.New("unable to read session ticket"))
			return
		}

		decrypted, err := aesutils.Decrypt(aesSessionTicketKey, decodedEncryptedSessionTicket)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		ss, err := ticket.Decode(decrypted)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		now := time.Now()
		if now.After(ss.ExpiresAt) {
			c.AbortWithError(http.StatusForbidden, errors.New("session expired"))
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		decodedBody, err := aesutils.Decrypt(ss.Secret, body)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(decodedBody))

		blw := encryptorBodyWriter{
			ResponseWriter: c.Writer,
			aesKey:         ss.Secret,
		}

		c.Writer = blw
		c.Next()
	}
}
