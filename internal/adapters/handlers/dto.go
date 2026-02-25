package handlers

type LoginRequest struct {
	UsernameOrEmail string `json:"username"`
	Password        string `json:"password"`
	RememberMe      bool   `json:"rememberMe"`
}

type LoginResponse struct {
	StatusCode int        `json:"statusCode"`
	Message    string     `json:"message"`
	Data       *TokenData `json:"data,omitempty"`
}

type TokenData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userId"`
	Role         string `json:"role"`
}
