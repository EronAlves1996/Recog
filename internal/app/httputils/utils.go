package httputils

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var ErrInternalServerError = errors.New("internal server error")

func AbortFailedToDeserialize(l *zap.SugaredLogger, c *gin.Context) {
	l.Errorw("Unable to desserialize message request struct")
	c.AbortWithError(http.StatusInternalServerError, ErrInternalServerError)
}
