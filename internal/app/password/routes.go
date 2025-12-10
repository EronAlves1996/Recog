package password

import (
	"github.com/EronAlves1996/Recog/internal/app/middleware"
	"github.com/gin-gonic/gin"
)

type HashPasswordBody struct {
	Password string `json:"password" binding:"required"`
}

type VerifyPasswordBody struct {
	HashPasswordBody
	HashedPassword string `json:"hashedPassword" binding:"required"`
}

func RegisterRoutes(r gin.IRouter) {
	rg := r.Group("password")

	rg.POST("/hash", middleware.ValidateMiddleware(HashPasswordBody{}), hashPassword())
	rg.POST("/verify", middleware.ValidateMiddleware(VerifyPasswordBody{}), verifyPassword())
}

func verifyPassword() gin.HandlerFunc {
	panic("unimplemented")
}

func hashPassword() gin.HandlerFunc {
	panic("unimplemented")
}
