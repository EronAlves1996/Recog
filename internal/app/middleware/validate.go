package middleware

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func ValidateMiddleware(val any) gin.HandlerFunc {
	value := reflect.ValueOf(val)
	if value.Kind() == reflect.Ptr {
		panic(`Bind struct can not be a pointer. Example:
	Use: gin.Bind(Struct{}) instead of gin.Bind(&Struct{})
`)
	}
	typ := value.Type()

	return func(c *gin.Context) {
		obj := reflect.New(typ).Interface()
		if err := c.ShouldBind(obj); err != nil {
			var validationErrors validator.ValidationErrors

			if ok, ok2 := c.Error(err).IsType(gin.ErrorTypeBind), errors.As(err, &validationErrors); ok && ok2 {

				errorResponse := make(map[string]string)
				for _, fieldErr := range validationErrors {
					errorResponse[fieldErr.Field()] = fieldErr.Tag()
				}
				c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": errorResponse})

			} else {
				// Handle other binding errors (e.g., malformed JSON)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			}
		} else {
			c.Set(gin.BindKey, obj)
		}
	}
}
