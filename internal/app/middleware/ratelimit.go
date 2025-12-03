package middleware

import (
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
}

func (b *Bucket) FillOne() bool {
	b.Leak()

	if b.Tickets == bucketSize {
		return false
	}

	b.Tickets += 1
	return true
}

func RateLimiter(logger *zap.SugaredLogger, redisClient *redis.Client) gin.HandlerFunc {
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
			if err := cmd.Scan(&bucket); err != nil {
				logger.Errorw("failed to deserialize bucket", zap.Error(cmd.Err()))
				c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
				return
			}

			if bucket.FillOne() {
				if !saveBucket(redisClient, rlk, bucket, logger, c) {
					return
				}
			} else {
				c.AbortWithStatus(http.StatusTooManyRequests)
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
	setCmd := redisClient.Set(ctx, bucketKey, b, 10*time.Minute)
	if setCmd.Err() != nil {
		logger.Errorw("something wrong in rate limiter", zap.Error(setCmd.Err()))
		c.AbortWithError(http.StatusInternalServerError, httputils.ErrInternalServerError)
		return false
	}

	return true
}
