package services

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
}

type TokenServiceInterface interface {
	Login(userNameOrEmail string, password string, rememberMe bool) (*TokenResponse, error)
	RefreshToken(refreshToken string) (*TokenResponse, error)
	Logout(refreshToken string) error
}
