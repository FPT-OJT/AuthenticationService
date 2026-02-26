package handlers

type LoginRequest struct {
	UsernameOrEmail string `json:"username" validate:"required"`
	Password        string `json:"password" validate:"required,min=8"`
	RememberMe      bool   `json:"rememberMe"`
}

type RegisterRequest struct {
	FirstName      string `json:"firstName" validate:"required"`
	LastName       string `json:"lastName" validate:"required"`
	Username       string `json:"username" validate:"required"`
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required,min=8"`
	RepeatPassword string `json:"repeatPassword" validate:"required,min=8"`
}

type TokenResponse struct {
	StatusCode int               `json:"statusCode"`
	Message    string            `json:"message"`
	Errors     map[string]string `json:"errors,omitempty"`
	Data       *TokenData        `json:"data,omitempty"`
}

type TokenData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userId"`
	Role         string `json:"role"`
}
