package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/coinbase/baseca/internal/config"
	"github.com/go-redis/redis/v8"
)

const (
	// Redis Cache (Maximum Certificates Issued Within Default Time) 5 Minutes
	_default_rate_limit = 0
	_default_window     = 1
	_default_period     = 5
)

type RedisIface interface {
	HIncrBy(ctx context.Context, key, field string, incr int64) *redis.IntCmd
	HGetAll(ctx context.Context, key string) *redis.StringStringMapCmd
	HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}
type RedisClient struct {
	Client RedisIface
	Config *config.RedisConfig

	// Sliding Window
	Limit    int
	Excluded []string
	Period   time.Duration
	Window   time.Duration
}

func NewRedisClient(config *config.Config) (*RedisClient, error) {
	redisConfig := &config.Redis
	endpoint := fmt.Sprintf("%s:%s", redisConfig.Endpoint, redisConfig.Port)
	client := redis.NewClient(&redis.Options{Addr: endpoint})

	if redisConfig.Period == 0 {
		redisConfig.Period = _default_period
	}

	if redisConfig.Duration == 0 {
		redisConfig.Duration = _default_window
	}

	if redisConfig.RateLimit == 0 {
		redisConfig.RateLimit = _default_rate_limit
	}

	if redisConfig.Duration > redisConfig.Period {
		return nil, fmt.Errorf("redis window duration [%d] must be greater than window period [%d]", redisConfig.Duration, redisConfig.Period)
	}

	return &RedisClient{
		Client:   client,
		Config:   redisConfig,
		Limit:    redisConfig.RateLimit,
		Excluded: redisConfig.ExcludeRateLimit,
		Period:   time.Duration(redisConfig.Period) * time.Minute,
		Window:   time.Duration(redisConfig.Duration) * time.Minute,
	}, nil
}
