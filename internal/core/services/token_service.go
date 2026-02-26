package services

import "errors"

var (
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrInvalidGoogleToken  = errors.New("invalid google token")
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
}

type TokenServiceInterface interface {
	Login(userNameOrEmail string, password string, rememberMe bool) (*TokenResponse, error)
	LoginWithGoogle(idToken string) (*TokenResponse, error)
	Register(firstName, lastName, username, email, password string) (*TokenResponse, error)
	RefreshToken(refreshToken string) (*TokenResponse, error)
	Logout(refreshToken string) error
}
