package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"authentication-service.com/internal/core/services"
	"github.com/go-playground/validator/v10"
)

type TokenHandler struct {
	tokenService services.TokenServiceInterface
	validate     *validator.Validate
}

func NewTokenHandler(tokenService services.TokenServiceInterface, validate *validator.Validate) *TokenHandler {
	return &TokenHandler{tokenService: tokenService, validate: validate}
}

// POST /auth/login
func (h *TokenHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "validation failed",
			Errors:     formatValidationErrors(err),
		})
		return
	}

	resp, err := h.tokenService.Login(req.UsernameOrEmail, req.Password, req.RememberMe)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			writeJSON(w, http.StatusUnauthorized, TokenResponse{
				StatusCode: http.StatusUnauthorized,
				Message:    "invalid username or password",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, TokenResponse{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		})
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
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

// POST /auth/register
func (h *TokenHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		})
		return
	}

	if err := h.validate.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "validation failed",
			Errors:     formatValidationErrors(err),
		})
		return
	}

	if req.Password != req.RepeatPassword {
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "passwords do not match",
		})
		return
	}

	resp, err := h.tokenService.Register(req.FirstName, req.LastName, req.Username, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrUserAlreadyExists) {
			writeJSON(w, http.StatusConflict, TokenResponse{
				StatusCode: http.StatusConflict,
				Message:    "user already exists",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, TokenResponse{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		})
		return
	}

	writeJSON(w, http.StatusCreated, TokenResponse{
		StatusCode: http.StatusCreated,
		Message:    "user registered successfully",
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
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "X-Refresh-Token header is required",
		})
		return
	}

	resp, err := h.tokenService.RefreshToken(refreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, TokenResponse{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
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
		writeJSON(w, http.StatusBadRequest, TokenResponse{
			StatusCode: http.StatusBadRequest,
			Message:    "X-Refresh-Token header is required",
		})
		return
	}

	if err := h.tokenService.Logout(refreshToken); err != nil {
		writeJSON(w, http.StatusUnauthorized, TokenResponse{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		StatusCode: http.StatusOK,
		Message:    "logged out successfully",
	})
}
