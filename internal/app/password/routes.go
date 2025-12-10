package password

import (
	"net/http"

	"github.com/EronAlves1996/Recog/internal/app/httputils"
	"github.com/EronAlves1996/Recog/internal/app/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type HashPasswordBody struct {
	Password string `json:"password" binding:"required,min=8,max=72"`
}

type VerifyPasswordBody struct {
	HashPasswordBody
	HashedPassword string `json:"hashedPassword" binding:"required"`
}

func RegisterRoutes(r gin.IRouter, l *zap.SugaredLogger, bcryptCost int) {
	rg := r.Group("password")

	rg.POST("/hash", middleware.ValidateMiddleware(HashPasswordBody{}), hashPassword(l, bcryptCost))
	rg.POST("/verify", middleware.ValidateMiddleware(VerifyPasswordBody{}), verifyPassword(l))
}

func verifyPassword(l *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, ok := c.MustGet(gin.BindKey).(*VerifyPasswordBody)
		if !ok {
			httputils.AbortFailedToDeserialize(l, c)
			return
		}

		password := body.Password
		hashedPassword := body.HashedPassword

		if len([]byte(password)) > 72 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Password exceeds maximum byte length (72 bytes)",
			})
			return
		}

		match := false

		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err == nil {
			match = true
		}

		c.JSON(http.StatusOK, gin.H{
			"match": match,
		})
	}
}

func hashPassword(l *zap.SugaredLogger, bcryptCost int) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, ok := c.MustGet(gin.BindKey).(*HashPasswordBody)
		if !ok {
			httputils.AbortFailedToDeserialize(l, c)
			return
		}

		password := body.Password

		if len([]byte(password)) > 72 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Password exceeds maximum byte length (72 bytes)",
			})
			return
		}

		// Already have built in salts https://stackoverflow.com/q/6832445
		cipherText, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			l.Errorw("failed to encrypt password", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to process password",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"hashedPassword": string(cipherText),
		})
	}
}
