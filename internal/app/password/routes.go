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
	Password string `json:"password" binding:"required,max=70"`
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

	panic("unimplemented")
}

func hashPassword(l *zap.SugaredLogger, bcryptCost int) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, ok := c.MustGet(gin.BindKey).(*HashPasswordBody)
		if !ok {
			httputils.AbortFailedToDeserialize(l, c)
			return
		}

		password := body.Password
		cipherText, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			l.Errorw("failed to encrypt password", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"hashedPassword": string(cipherText),
		})
	}
}
