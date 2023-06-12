package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

func (r *RedisClient) Increment(ctx context.Context, key string, increment int) error {
	utc := time.Now().UTC()
	timestamp := fmt.Sprint(utc.Truncate(r.Window).Unix())

	value, err := r.Client.HIncrBy(ctx, key, timestamp, int64(increment)).Result()
	if err != nil {
		return err
	}

	if value == 1 {
		r.Client.Expire(ctx, key, r.Period)
	} else if value >= int64(r.Limit) {
		return fmt.Errorf("rate limit [%d], time period [%v], reset time: [%v], current limit: [%d]", r.Limit, r.Period, utc.Add(r.Period), value)
	}

	values, err := r.Client.HGetAll(ctx, key).Result()
	if err != nil {
		return err
	}

	threshold := fmt.Sprint(utc.Add(-r.Period).Unix())

	aggregate := 0
	for time, count := range values {
		if time > threshold {
			i, _ := strconv.Atoi(count)
			aggregate += i
		} else {
			r.Client.HDel(ctx, key, time)
		}
	}

	if aggregate >= r.Limit {
		return fmt.Errorf("rate limit [%d], time period [%v], reset time: [%v], current aggregate: [%d]", r.Limit, r.Period, utc.Add(r.Period), aggregate)
	}

	return nil
}
