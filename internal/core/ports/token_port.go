package ports

import "github.com/golang-jwt/jwt/v5"

type AccessTokenData struct {
	AccessToken string
	UserID      string
	Role        string
	FamilyToken string
}

type TokenPort interface {
	GenerateAccessToken(userID string, familyToken string, role string) (string, error)
	GenerateRefreshToken(userID string, familyToken string, role string, rememberMe bool) (string, error)
	GenerateAccessTokenByRefreshToken(refreshToken string) (*AccessTokenData, error)
	ValidateToken(token string) error
	ExtractClaims(token string) (jwt.MapClaims, error)
	RevokeByFamilyToken(familyToken string) error
	RevokeByRefreshToken(refreshToken string) error
}
