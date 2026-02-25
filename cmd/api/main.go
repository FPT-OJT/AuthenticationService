package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	jwtadapter "authentication-service.com/internal/adapters/jwt_adapter"
	repositories "authentication-service.com/internal/adapters/repositories"
	"authentication-service.com/internal/adapters/handlers"
	dbAdapter "authentication-service.com/internal/infrastructure/database"
	"authentication-service.com/internal/infrastructure/routes"
	services_impl "authentication-service.com/internal/core/services/impl"
	"authentication-service.com/internal/pkg"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
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
	log.Printf("Loaded RSA private key from %s\n", privateKeyPath)

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
	log.Printf("Redis: Connected to %s:%s\n", redisConfig.Host, redisConfig.Port)

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
	log.Printf("PostgreSQL: Connected to %s:%s/%s\n", pgConfig.Host, pgConfig.Port, pgConfig.DBName)

	// Wire dependencies
	refreshTokenRepo := repositories.NewRedisRefreshTokenRepository(redisClient)
	userRepo := repositories.NewUserRepository(db)

	accessTokenTTL := time.Duration(pkg.GetEnvAsInt("JWT_ACCESS_TOKEN_TTL_MINUTES", 15)) * time.Minute
	refreshTokenTTL := time.Duration(pkg.GetEnvAsInt("JWT_REFRESH_TOKEN_TTL_DAYS", 7)) * 24 * time.Hour
	refreshTokenRememberMeTTL := time.Duration(pkg.GetEnvAsInt("JWT_REFRESH_TOKEN_REMEMBER_ME_TTL_DAYS", 30)) * 24 * time.Hour

	tokenGen := jwtadapter.NewRSAJWTGenerator(
		privateKey,
		accessTokenTTL,
		refreshTokenTTL,
		refreshTokenRememberMeTTL,
		refreshTokenRepo,
	)

	tokenService := services_impl.NewTokenService(userRepo, tokenGen)
	tokenHandler := handlers.NewTokenHandler(tokenService)

	// Register routes
	mux := http.NewServeMux()
	routes.RegisterRoutes(mux, tokenHandler)

	server := &http.Server{
		Addr:    ":" + serverPort,
		Handler: mux,
	}

	// Start server
	go func() {
		log.Printf("Server started on port %s\n", serverPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped")
}
