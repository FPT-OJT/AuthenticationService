package handlers

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Data       *Data  `json:"data,omitempty"`
}

type Data struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
