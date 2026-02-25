package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	dbAdapter "authentication-service.com/internal/adapters/database"
	"authentication-service.com/internal/pkg"
)

func main() {
	// Load PostgreSQL configuration
	pgConfig := dbAdapter.PostgresConfig{
		Host:            pkg.GetEnvAsString("POSTGRESQL_HOST", "localhost"),
		Port:            pkg.GetEnvAsString("POSTGRESQL_EXTERNAL_PORT", "5432"),
		User:            pkg.GetEnvAsString("AUTH_POSTGRES_USER", "postgres"),
		Password:        pkg.GetEnvAsString("AUTH_POSTGRES_PASSWORD", "postgres"),
		DBName:          pkg.GetEnvAsString("AUTH_POSTGRES_DB", "auth_db"),
		MaxIdleConns:    pkg.GetEnvAsInt("POSTGRESQL_MAX_IDLE_CONNS", 10),
		MaxOpenConns:    pkg.GetEnvAsInt("POSTGRESQL_MAX_OPEN_CONNS", 100),
		ConnMaxLifetime: pkg.GetEnvAsInt("POSTGRESQL_CONN_MAX_LIFETIME", 3600),
	}

	// Initialize PostgreSQL
	db, err := dbAdapter.InitPostgres(pgConfig)
	if err != nil {
		log.Fatal("Failed to connect to PostgreSQL: " + err.Error())
	}
	defer func() {
		sqlDB, err := db.DB()
		if err != nil {
			log.Println("Error getting DB instance:", err)
			return
		}
		if err := sqlDB.Close(); err != nil {
			log.Println("Error closing PostgreSQL:", err)
		} else {
			log.Println("PostgreSQL connection closed")
		}
	}()

	// Load Redis configuration
	redisConfig := dbAdapter.RedisConfig{
		Host:         pkg.GetEnvAsString("REDIS_HOST", "localhost"),
		Port:         pkg.GetEnvAsString("REDIS_EXTERNAL_PORT", "6379"),
		Password:     pkg.GetEnvAsString("REDIS_PASSWORD", ""),
		DB:           pkg.GetEnvAsInt("REDIS_DB", 0),
		DialTimeout:  pkg.GetEnvAsInt("REDIS_DIAL_TIMEOUT", 5),
		ReadTimeout:  pkg.GetEnvAsInt("REDIS_READ_TIMEOUT", 3),
		WriteTimeout: pkg.GetEnvAsInt("REDIS_WRITE_TIMEOUT", 3),
		PoolSize:     pkg.GetEnvAsInt("REDIS_POOL_SIZE", 10),
		MinIdleConns: pkg.GetEnvAsInt("REDIS_MIN_IDLE_CONNS", 5),
	}

	// Initialize Redis
	redisClient, err := dbAdapter.InitRedis(redisConfig)
	if err != nil {
		log.Fatal("Failed to connect to Redis: " + err.Error())
	}
	defer func() {
		if err := redisClient.Close(); err != nil {
			log.Println("Error closing Redis:", err)
		} else {
			log.Println("Redis connection closed")
		}
	}()

	log.Println("Database connections established successfully")
	log.Printf("PostgreSQL: Connected to %s:%s/%s\n", pgConfig.Host, pgConfig.Port, pgConfig.DBName)
	log.Printf("Redis: Connected to %s:%s\n", redisConfig.Host, redisConfig.Port)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down gracefully...")
}
