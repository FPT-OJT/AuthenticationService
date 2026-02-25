package pkg

import (
	"os"
	"strconv"
)

func GetEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}

func GetEnvAsString(key string, defaultVal string) string {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	return valStr
}
