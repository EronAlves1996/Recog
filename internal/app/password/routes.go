package password

import (
	"github.com/EronAlves1996/Recog/internal/app/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type HashPasswordBody struct {
	Password string `json:"password" binding:"required"`
}

type VerifyPasswordBody struct {
	HashPasswordBody
	HashedPassword string `json:"hashedPassword" binding:"required"`
}

func RegisterRoutes(r gin.IRouter, l *zap.SugaredLogger) {
	rg := r.Group("password")

	rg.POST("/hash", middleware.ValidateMiddleware(HashPasswordBody{}), hashPassword(l))
	rg.POST("/verify", middleware.ValidateMiddleware(VerifyPasswordBody{}), verifyPassword(l))
}

func verifyPassword(l *zap.SugaredLogger) gin.HandlerFunc {

	panic("unimplemented")
}

func hashPassword(l *zap.SugaredLogger) gin.HandlerFunc {
	panic("unimplemented")
}
