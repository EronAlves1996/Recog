package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/EronAlves1996/Recog/internal/app/httputils"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var lock sync.Mutex

func createRateLimiterKey(ip string) string {
	return fmt.Sprintf("rl-%s", ip)
}

// How much tickets it gonna leak per second
const bucketLeakRate = 3
const bucketSize = 50

type Bucket struct {
	Tickets     int
	LastUpdated time.Time
}

func newBucket() Bucket {
	return Bucket{
		LastUpdated: time.Now(),
	}
}

func (b *Bucket) Leak() {
	if b.Tickets == 0 {
		return
	}

	now := time.Now()
	diff := now.Sub(b.LastUpdated)
	s := diff.Seconds()
	toLeak := int(s) * bucketLeakRate
	updatedTickets := b.Tickets - toLeak

	if updatedTickets < 0 {
		b.Tickets = 0
	} else {
		b.Tickets = updatedTickets
	}

	b.LastUpdated = now
}

func (b *Bucket) FillOne() bool {
	b.Leak()

	if b.Tickets == bucketSize {
		return false
	}

	b.Tickets += 1
	b.LastUpdated = time.Now()
	return true
}

func RateLimiter(logger *zap.SugaredLogger,
	auditLogger *zap.SugaredLogger,
	redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		lock.Lock()
		ip := c.ClientIP()
		rlk := createRateLimiterKey(ip)
		cmd := redisClient.Get(c.Request.Context(), rlk)

		if cmd.Err() != nil {
			if errors.Is(cmd.Err(), redis.Nil) {
				b := newBucket()
				b.FillOne()

				if !saveBucket(redisClient, rlk, b, logger, c) {
					return
				}

			} else {
				logger.Errorw("something wrong in rate limiter", zap.Error(cmd.Err()))
				c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
				return
			}
		} else {
			var bucket Bucket
			marshalledBucket, err := cmd.Bytes()
			if err != nil {
				logger.Errorw("failed to get bucket in bytes", zap.Error(err))
				c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
				return
			}

			if err := json.Unmarshal(marshalledBucket, &bucket); err != nil {
				logger.Errorw("failed to deserialize bucket", zap.Error(err))
				c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
				return
			}

			if bucket.FillOne() {
				if !saveBucket(redisClient, rlk, bucket, logger, c) {
					return
				}
			} else {
				c.AbortWithStatus(http.StatusTooManyRequests)
				auditLogger.With(
					"client_ip", ip,
					"endpoint", c.Request.RequestURI,
					"timestamp", time.Now(),
					"request_count", bucket.Tickets,
					"limit", bucketSize,
				).Info()
			}
		}

		defer func() {
			lock.Unlock()
			c.Next()
		}()
	}
}

func saveBucket(redisClient *redis.Client, bucketKey string, b Bucket, logger *zap.SugaredLogger, c *gin.Context) bool {
	ctx := c.Request.Context()
	j, err := json.Marshal(b)
	if err != nil {
		logger.Errorw("something wrong in rate limiter", zap.Error(err))
		c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
		return false
	}

	setCmd := redisClient.Set(ctx, bucketKey, j, 10*time.Minute)
	if setCmd.Err() != nil {
		logger.Errorw("something wrong in rate limiter", zap.Error(setCmd.Err()))
		c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
		return false
	}

	return true
}
