package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"authentication-service.com/internal/core/services"
	services_impl "authentication-service.com/internal/core/services/impl"
)

type TokenHandler struct {
	tokenService services.TokenServiceInterface
}

func NewTokenHandler(tokenService services.TokenServiceInterface) *TokenHandler {
	return &TokenHandler{tokenService: tokenService}
}

// POST /auth/login
func (h *TokenHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, LoginResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		})
		return
	}

	if req.UsernameOrEmail == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "username_or_email and password are required",
		})
		return
	}

	resp, err := h.tokenService.Login(req.UsernameOrEmail, req.Password, req.RememberMe)
	if err != nil {
		if errors.Is(err, services_impl.ErrInvalidCredentials) {
			writeJSON(w, http.StatusUnauthorized, LoginResponse{
				StatusCode: http.StatusUnauthorized,
				Message:    "invalid username or password",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, LoginResponse{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		StatusCode: http.StatusOK,
		Message:    "login successful",
		Data: &TokenData{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			UserID:       resp.UserID,
			Role:         resp.Role,
		},
	})
}

// POST /auth/refresh
func (h *TokenHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("X-Refresh-Token")
	if refreshToken == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "X-Refresh-Token header is required",
		})
		return
	}

	resp, err := h.tokenService.RefreshToken(refreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, LoginResponse{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		StatusCode: http.StatusOK,
		Message:    "token refreshed",
		Data: &TokenData{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			UserID:       resp.UserID,
			Role:         resp.Role,
		},
	})
}

// POST /auth/logout
func (h *TokenHandler) Logout(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("X-Refresh-Token")
	if refreshToken == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "X-Refresh-Token header is required",
		})
		return
	}

	if err := h.tokenService.Logout(refreshToken); err != nil {
		writeJSON(w, http.StatusUnauthorized, LoginResponse{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		StatusCode: http.StatusOK,
		Message:    "logged out successfully",
	})
}
