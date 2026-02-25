package database

import (
	"fmt"
	"log"
	"time"

	"authentication-service.com/internal/pkg"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitPostgres() (*gorm.DB, error) {
	host := pkg.GetEnvAsString("POSTGRESQL_HOST", "localhost")
	port := pkg.GetEnvAsString("POSTGRESQL_EXTERNAL_PORT", "5432")
	user := pkg.GetEnvAsString("AUTH_POSTGRES_USER", "postgres")
	password := pkg.GetEnvAsString("AUTH_POSTGRES_PASSWORD", "postgres")
	dbname := pkg.GetEnvAsString("AUTH_POSTGRES_DB", "auth_db")

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Ho_Chi_Minh",
		host, user, password, dbname, port,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	DB = db
	log.Println("PostgreSQL connected successfully")
	return db, nil
}

func ClosePostgres() error {
	if DB != nil {
		sqlDB, err := DB.DB()
		if err != nil {
			return fmt.Errorf("failed to get database instance: %w", err)
		}
		if err := sqlDB.Close(); err != nil {
			return fmt.Errorf("failed to close postgres connection: %w", err)
		}
		log.Println("PostgreSQL connection closed")
	}
	return nil
}
