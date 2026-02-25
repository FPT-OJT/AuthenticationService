package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"authentication-service.com/internal/pkg"
	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func InitRedis() (*redis.Client, error) {
	host := pkg.GetEnvAsString("REDIS_HOST", "localhost")
	port := pkg.GetEnvAsString("REDIS_EXTERNAL_PORT", "6379")
	password := pkg.GetEnvAsString("REDIS_PASSWORD", "")
	db := pkg.GetEnvAsInt("REDIS_DB", 0)
	dialTimeout := pkg.GetEnvAsInt("REDIS_DIAL_TIMEOUT", 5)
	readTimeout := pkg.GetEnvAsInt("REDIS_READ_TIMEOUT", 3)
	writeTimeout := pkg.GetEnvAsInt("REDIS_WRITE_TIMEOUT", 3)
	poolSize := pkg.GetEnvAsInt("REDIS_POOL_SIZE", 10)
	minIdleConns := pkg.GetEnvAsInt("REDIS_MIN_IDLE_CONNS", 5)

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", host, port),
		Password:     password,
		DB:           db,
		DialTimeout:  time.Duration(dialTimeout) * time.Second,
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
		PoolSize:     poolSize,
		MinIdleConns: minIdleConns,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	RedisClient = client
	log.Println("Redis connected successfully")
	return client, nil
}

func CloseRedis() error {
	if RedisClient != nil {
		if err := RedisClient.Close(); err != nil {
			return fmt.Errorf("failed to close redis connection: %w", err)
		}
		log.Println("Redis connection closed")
	}
	return nil
}
