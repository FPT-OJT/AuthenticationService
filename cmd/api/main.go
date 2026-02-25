package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	dbAdapter "authentication-service.com/internal/adapters/database"
)

func main() {
	postgres, err := dbAdapter.InitPostgres()
	if err != nil {
		log.Fatal("Failed to connect to PostgreSQL: " + err.Error())
	}
	defer func() {
		if err := dbAdapter.ClosePostgres(); err != nil {
			log.Println("Error closing PostgreSQL:", err)
		}
	}()

	redis, err := dbAdapter.InitRedis()
	if err != nil {
		log.Fatal("Failed to connect to Redis: " + err.Error())
	}
	defer func() {
		if err := dbAdapter.CloseRedis(); err != nil {
			log.Println("Error closing Redis:", err)
		}
	}()

	log.Println("Database connections established successfully")
	log.Printf("PostgreSQL: %v\n", postgres)
	log.Printf("Redis: %v\n", redis)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down gracefully...")
}
