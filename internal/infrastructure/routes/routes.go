package routes

import (
	"net/http"

	"authentication-service.com/internal/adapters/handlers"
)

func RegisterRoutes(mux *http.ServeMux, tokenHandler *handlers.TokenHandler) {
	mux.HandleFunc("POST /public/auth/login", tokenHandler.Login)
	mux.HandleFunc("POST /public/auth/register", tokenHandler.Register)
	mux.HandleFunc("POST /public/auth/refresh", tokenHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", tokenHandler.Logout)
}
