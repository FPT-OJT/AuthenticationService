package jwtadapter

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"authentication-service.com/internal/core/domain"
	"authentication-service.com/internal/core/ports"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrRefreshTokenExpired = errors.New("refresh token has expired or not found")
	ErrRefreshTokenRevoked = errors.New("refresh token has already been revoked")
	ErrSuspiciousActivity  = errors.New("refresh token reuse detected - potential replay attack")
)

type RSAJWTGenerator struct {
	privateKey                *rsa.PrivateKey
	publicKey                 *rsa.PublicKey
	accessTokenTTL            time.Duration
	refreshTokenTTL           time.Duration
	refreshTokenRememberMeTTL time.Duration
	refreshTokenRepo          ports.RefreshTokenRepositoryPort
}

func NewRSAJWTGenerator(
	privateKey *rsa.PrivateKey,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenRememberMeTTL time.Duration,
	refreshTokenRepo ports.RefreshTokenRepositoryPort,
) *RSAJWTGenerator {
	return &RSAJWTGenerator{
		privateKey:                privateKey,
		publicKey:                 &privateKey.PublicKey,
		accessTokenTTL:            accessTokenTTL,
		refreshTokenTTL:           refreshTokenTTL,
		refreshTokenRememberMeTTL: refreshTokenRememberMeTTL,
		refreshTokenRepo:          refreshTokenRepo,
	}
}

func (g *RSAJWTGenerator) GenerateAccessToken(userID string, familyToken string, role string) (string, error) {
	return g.generateToken(userID, familyToken, role, g.accessTokenTTL)
}

func (g *RSAJWTGenerator) GenerateRefreshToken(userID string, familyToken string, role string, rememberMe bool) (string, error) {
	if familyToken != "" {
		existingTokens, err := g.refreshTokenRepo.FindAllByFamilyToken(familyToken)
		if err != nil {
			return "", fmt.Errorf("failed to find existing tokens: %w", err)
		}
		for _, rt := range existingTokens {
			rt.IsRevoked = true
		}
		if err := g.refreshTokenRepo.SaveAll(existingTokens); err != nil {
			return "", fmt.Errorf("failed to revoke existing tokens: %w", err)
		}
	}

	if familyToken == "" {
		familyToken = newUUID()
	}

	ttl := g.refreshTokenTTL
	if rememberMe {
		ttl = g.refreshTokenRememberMeTTL
	}

	tokenString, err := g.generateToken(userID, familyToken, role, ttl)
	if err != nil {
		return "", err
	}

	// Lưu vào Redis
	entity := &domain.RefreshToken{
		RefreshToken: tokenString,
		FamilyToken:  familyToken,
		UserID:       userID,
		Role:         role,
		IsRevoked:    false,
	}
	if err := g.refreshTokenRepo.Save(entity, ttl); err != nil {
		return "", fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}

	return tokenString, nil
}

func (g *RSAJWTGenerator) GenerateAccessTokenByRefreshToken(refreshToken string) (*ports.AccessTokenData, error) {
	stored, err := g.refreshTokenRepo.FindByRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrRefreshTokenExpired
	}

	result, err := g.refreshTokenRepo.AtomicRevoke(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("atomic revoke failed: %w", err)
	}

	switch result {
	case -1:
		return nil, ErrRefreshTokenExpired
	case 0:
		_ = g.RevokeByFamilyToken(stored.FamilyToken)
		return nil, ErrSuspiciousActivity
	}

	// Bước 3: tạo access token mới
	accessToken, err := g.GenerateAccessToken(stored.UserID, stored.FamilyToken, stored.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &ports.AccessTokenData{
		AccessToken: accessToken,
		UserID:      stored.UserID,
		Role:        stored.Role,
		FamilyToken: stored.FamilyToken,
	}, nil
}

// RevokeByFamilyToken revoke toàn bộ refresh token thuộc cùng một family.
func (g *RSAJWTGenerator) RevokeByFamilyToken(familyToken string) error {
	tokens, err := g.refreshTokenRepo.FindAllByFamilyToken(familyToken)
	if err != nil {
		return fmt.Errorf("failed to find tokens by family: %w", err)
	}
	for _, rt := range tokens {
		rt.IsRevoked = true
	}
	if err := g.refreshTokenRepo.SaveAll(tokens); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}
	return nil
}

func (g *RSAJWTGenerator) RevokeByRefreshToken(refreshToken string) error {
	stored, err := g.refreshTokenRepo.FindByRefreshToken(refreshToken)
	if err != nil {
		return ErrRefreshTokenExpired
	}
	if stored.IsRevoked {
		return ErrSuspiciousActivity
	}
	stored.IsRevoked = true
	return g.refreshTokenRepo.SaveAll([]*domain.RefreshToken{stored})
}

func (g *RSAJWTGenerator) ValidateToken(token string) error {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return g.publicKey, nil
	})
	return err
}

func (g *RSAJWTGenerator) ExtractClaims(token string) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return g.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return claims, nil
}

func (g *RSAJWTGenerator) generateToken(userID string, familyToken string, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":          userID,
		"role":         "ROLE_" + role,
		"family_token": familyToken,
		"iat":          now.Unix(),
		"exp":          now.Add(ttl).Unix(),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := t.SignedString(g.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return signed, nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
