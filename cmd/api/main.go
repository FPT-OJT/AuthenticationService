package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	jwtadapter "authentication-service.com/internal/adapters/jwt_adapter"
	dbAdapter "authentication-service.com/internal/infrastructure/database"
	"authentication-service.com/internal/pkg"
	"github.com/golang-jwt/jwt/v5"
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

	privateKeyPath := pkg.GetEnvAsString("JWT_PRIVATE_KEY_PATH", "private_key.pem")
	serverPort := pkg.GetEnvAsString("SERVER_PORT", "8080")

	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("FAIL-FAST: Cannot read file Private Key tại %s: %v", privateKeyPath, err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatalf("FAIL-FAST: Error format PEM of Private Key: %v", err)
	}
	tokenGen := jwtadapter.NewRSAJWTGenerator(privateKey)

	log.Printf("Jwt private key: %v", tokenGen)
	log.Printf("Server will start on port %s\n", serverPort)

	log.Printf("Loaded RSA private key from %s\n", privateKeyPath)

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
