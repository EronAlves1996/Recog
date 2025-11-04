package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Return struct {
	Hash string
}

func main() {
	router := gin.Default()
	logger, _ := zap.NewProduction()

	l := logger.Sugar()
	router.POST("/file/hash", func(c *gin.Context) {
		h := c.Request.Header.Get("Content-Type")

		if h == "" {
			c.AbortWithError(400, errors.New("Content-Type header is required"))
			return
		}

		if !strings.Contains(h, "multipart/form-data") {
			c.AbortWithError(http.StatusUnsupportedMediaType, errors.New("the correct content type for this request is multipart form data"))
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			l.Errorw("Error while opening the file", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errors.New("internal server error"))
			return
		}

		openedFile, err := file.Open()
		if err != nil {
			l.Errorw("Error while opening the file", zap.Error(err))
			c.AbortWithError(http.StatusInternalServerError, errors.New("internal server error"))
			return
		}

		b := make([]byte, 512)
		hasher := crypto.SHA256.New()

		for {
			n, err := openedFile.Read(b)

			if errors.Is(err, io.EOF) {
				break
			}

			if err != nil {
				l.Errorw("Error while reading the file", zap.Error(err))
				c.AbortWithError(http.StatusInternalServerError, errors.New("internal server error"))
				return
			}

			hasher.Write(b[:n])
		}

		hashed := hasher.Sum(nil)
		hashString := hex.EncodeToString(hashed)

		ret := Return{
			Hash: hashString,
		}

		c.JSON(http.StatusOK, ret)
	})

	l.Info("Listening on 8080")
	router.Run()
}
