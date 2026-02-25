package services_impl

import (
	"errors"

	"authentication-service.com/internal/core/ports"
	"authentication-service.com/internal/core/services"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
)

type TokenService struct {
	userRepo  ports.UserRepositoryPort
	tokenPort ports.TokenPort
}

func NewTokenService(userRepo ports.UserRepositoryPort, tokenPort ports.TokenPort) *TokenService {
	return &TokenService{
		userRepo:  userRepo,
		tokenPort: tokenPort,
	}
}

func (s *TokenService) Login(usernameOrEmail string, password string, rememberMe bool) (*services.TokenResponse, error) {
	user, err := s.userRepo.FindByUsernameOrEmail(usernameOrEmail)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	refreshToken, err := s.tokenPort.GenerateRefreshToken(user.ID, "", user.Role, rememberMe)
	if err != nil {
		return nil, err
	}

	claims, err := s.tokenPort.ExtractClaims(refreshToken)
	if err != nil {
		return nil, err
	}
	familyToken, _ := claims["family_token"].(string)

	accessToken, err := s.tokenPort.GenerateAccessToken(user.ID, familyToken, user.Role)
	if err != nil {
		return nil, err
	}

	return &services.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Role:         user.Role,
	}, nil
}

func (s *TokenService) RefreshToken(refreshToken string) (*services.TokenResponse, error) {
	data, err := s.tokenPort.GenerateAccessTokenByRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return &services.TokenResponse{
		AccessToken:  data.AccessToken,
		RefreshToken: refreshToken,
		UserID:       data.UserID,
		Role:         data.Role,
	}, nil
}

func (s *TokenService) Logout(refreshToken string) error {
	return s.tokenPort.RevokeByRefreshToken(refreshToken)
}
