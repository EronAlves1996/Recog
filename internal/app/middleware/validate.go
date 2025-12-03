package middleware

import (
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func init() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
			return strings.TrimSpace(fl.Field().String()) != ""
		})
	}
}

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

			if ok := errors.As(err, &validationErrors); ok {

				errorResponse := make(map[string]string)
				for _, fieldErr := range validationErrors {
					errorResponse[fieldErr.Field()] = fieldErr.Tag()
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": errorResponse})

			} else {
				// Handle other binding errors (e.g., malformed JSON)
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			}
		} else {
			c.Set(gin.BindKey, obj)
		}
	}
}
