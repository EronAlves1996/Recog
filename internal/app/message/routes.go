package message

import (
	"bytes"
	"crypto"
	"net/http"

	"github.com/EronAlves1996/Recog/internal/app/hash"
	"github.com/EronAlves1996/Recog/internal/app/httputils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type HashBody struct {
	Message string `json:"message" binding:"required"`
}

func RegisterRoutes(router *gin.Engine, logger *zap.SugaredLogger) {
	g := router.Group("/message")

	g.POST("/hash", gin.Bind(HashBody{}), hashBody(logger))
}

func hashBody(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, ok := c.MustGet(gin.BindKey).(*HashBody)
		if !ok {
			httputils.AbortFailedToDesserialize(logger, c)
			return
		}

		hasher := crypto.SHA256.New()
		var buf bytes.Buffer
		buf.WriteString(body.Message)

		message, err := hash.Hash(logger, hasher, &buf)
		if err != nil {
			logger.Errorw("failed to hash message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"hash": message,
		})
	}
}
