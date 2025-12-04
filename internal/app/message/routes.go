package message

import (
	"crypto"
	"net/http"
	"strings"

	"github.com/EronAlves1996/Recog/internal/app/hash"
	"github.com/EronAlves1996/Recog/internal/app/httputils"
	"github.com/EronAlves1996/Recog/internal/app/middleware"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	_ "github.com/go-playground/validator/v10"
)

type HashBody struct {
	Message string `json:"message" binding:"required,min=1,max=100,notblank"`
}

func RegisterRoutes(router *gin.Engine, logger, auditLogger *zap.SugaredLogger,
	redisClient *redis.Client, aesSessionTicketKey []byte) {
	g := router.Group("/message")

	g.POST("/hash", middleware.RateLimiter(logger, auditLogger, redisClient),
		middleware.ValidateMiddleware(HashBody{}), hashBody(logger))
	g.POST("/hash/secure", middleware.RateLimiter(logger, auditLogger, redisClient),
		middleware.ProtectDataMiddleware(aesSessionTicketKey),
		middleware.ValidateMiddleware(HashBody{}), hashBody(logger))
}

func hashBody(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, ok := c.MustGet(gin.BindKey).(*HashBody)
		if !ok {
			httputils.AbortFailedToDeserialize(logger, c)
			return
		}

		hasher := crypto.SHA256.New()
		hashString, err := hash.Hash(hasher, strings.NewReader(body.Message))
		if err != nil {
			logger.Errorw("failed to hash message", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"hash": hashString,
		})
	}
}
