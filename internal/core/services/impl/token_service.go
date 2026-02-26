package services_impl

import (
	"context"
	"errors"
	"fmt"
	"log"

	"authentication-service.com/internal/core/domain"
	"authentication-service.com/internal/core/ports"
	"authentication-service.com/internal/core/services"
	"golang.org/x/crypto/bcrypt"
)

type TokenService struct {
	userRepo       ports.UserRepositoryPort
	tokenPort      ports.TokenPort
	eventPublisher ports.EventPublisherPort
	googleVerifier ports.GoogleTokenVerifierPort
}

func NewTokenService(userRepo ports.UserRepositoryPort, tokenPort ports.TokenPort, eventPublisher ports.EventPublisherPort, googleVerifier ports.GoogleTokenVerifierPort) *TokenService {
	return &TokenService{
		userRepo:       userRepo,
		tokenPort:      tokenPort,
		eventPublisher: eventPublisher,
		googleVerifier: googleVerifier,
	}
}

func (s *TokenService) Login(usernameOrEmail string, password string, rememberMe bool) (*services.TokenResponse, error) {
	user, err := s.userRepo.FindByUsernameOrEmail(usernameOrEmail)
	if err != nil {
		return nil, services.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, services.ErrInvalidCredentials
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

func (s *TokenService) Register(firstName, lastName, username, email, password string) (*services.TokenResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		Username: username,
		Email:    email,
		Role:     "CUSTOMER",
		Password: string(hashedPassword),
	}

	user, err = s.userRepo.Create(user)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			return nil, services.ErrUserAlreadyExists
		}
		return nil, err
	}

	refreshToken, err := s.tokenPort.GenerateRefreshToken(user.ID, "", user.Role, false)
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

	if err := s.eventPublisher.PublishUserCreated(context.Background(), domain.UserCreatedEvent{
		FirstName: firstName,
		LastName:  lastName,
		Email:     user.Email,
	}); err != nil {
		log.Printf("Failed to publish UserCreatedEvent for email %s: %v", user.Email, err)
		return nil, fmt.Errorf("failed to publish event: %w", err)
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

// LoginWithGoogle verifies the Google ID token, then finds-or-creates the user
func (s *TokenService) LoginWithGoogle(idToken string) (*services.TokenResponse, error) {
	payload, err := s.googleVerifier.Verify(idToken)
	if err != nil {
		log.Printf("Google token verification failed: %v", err)
		return nil, services.ErrInvalidGoogleToken
	}

	user, err := s.handleGoogleCredential(payload)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokenPort.GenerateRefreshToken(user.ID, "", user.Role, false)
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

	log.Printf("Google login successful for email=%s userID=%s", user.Email, user.ID)
	return &services.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Role:         user.Role,
	}, nil
}

// 1. Find by GoogleID → return existing user
// 2. Find by email → link GoogleID to existing account
// 3. Otherwise → create new user
func (s *TokenService) handleGoogleCredential(payload *ports.GoogleTokenPayload) (*domain.User, error) {
	// 1. Already linked
	if user, err := s.userRepo.FindByGoogleID(payload.GoogleID); err == nil {
		return user, nil
	}

	// 2. Existing email account — link google id
	if user, err := s.userRepo.FindByUsernameOrEmail(payload.Email); err == nil {
		user.GoogleID = payload.GoogleID
		return s.userRepo.Update(user)
	}

	// 3. New user
	newUser := &domain.User{
		Username: payload.Email,
		Email:    payload.Email,
		GoogleID: payload.GoogleID,
		Role:     "CUSTOMER",
	}
	return s.userRepo.Create(newUser)
}
