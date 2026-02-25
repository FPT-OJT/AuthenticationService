package jwtadapter

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type RSAJWTGenerator struct {
	privateKey *rsa.PrivateKey
}

func NewRSAJWTGenerator(key *rsa.PrivateKey) *RSAJWTGenerator {
	return &RSAJWTGenerator{
		privateKey: key,
	}
}

func (g *RSAJWTGenerator) GenerateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(g.privateKey)
	if err != nil {
		return "", fmt.Errorf("Error when sign JWT: %w", err)
	}

	return signedToken, nil
}
