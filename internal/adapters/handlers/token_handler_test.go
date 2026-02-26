package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"authentication-service.com/internal/core/services"
	"github.com/go-playground/validator/v10"
)

// ---------------------------------------------------------------------------
// Mock TokenService
// ---------------------------------------------------------------------------

type mockTokenService struct {
	loginFn           func(string, string, bool) (*services.TokenResponse, error)
	loginWithGoogleFn func(string) (*services.TokenResponse, error)
	registerFn        func(string, string, string, string, string) (*services.TokenResponse, error)
	refreshTokenFn    func(string) (*services.TokenResponse, error)
	logoutFn          func(string) error
}

func (m *mockTokenService) Login(u, p string, r bool) (*services.TokenResponse, error) {
	return m.loginFn(u, p, r)
}
func (m *mockTokenService) LoginWithGoogle(idToken string) (*services.TokenResponse, error) {
	return m.loginWithGoogleFn(idToken)
}
func (m *mockTokenService) Register(fn, ln, username, email, password string) (*services.TokenResponse, error) {
	return m.registerFn(fn, ln, username, email, password)
}
func (m *mockTokenService) RefreshToken(rt string) (*services.TokenResponse, error) {
	return m.refreshTokenFn(rt)
}
func (m *mockTokenService) Logout(rt string) error {
	return m.logoutFn(rt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newValidator() *validator.Validate {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Tag.Get("json")
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})
	return v
}

func newHandler(svc services.TokenServiceInterface) *TokenHandler {
	return NewTokenHandler(svc, newValidator())
}

func decodeBody(t *testing.T, body *bytes.Buffer) TokenResponse {
	t.Helper()
	var resp TokenResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return resp
}

func makeJSONRequest(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("failed to encode request body: %v", err)
	}
	req := httptest.NewRequest(method, target, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}

var tokenServiceResponse = &services.TokenResponse{
	AccessToken:  "access-tok",
	RefreshToken: "refresh-tok",
	UserID:       "user-1",
	Role:         "CUSTOMER",
}

// ---------------------------------------------------------------------------
// Login handler tests
// ---------------------------------------------------------------------------

func TestLoginHandler_Success(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginFn: func(_, _ string, _ bool) (*services.TokenResponse, error) {
			return tokenServiceResponse, nil
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/login", map[string]any{
		"username": "testuser",
		"password": "password123",
	})
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want %d, got %d", http.StatusOK, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Data == nil {
		t.Fatal("expected Data in response, got nil")
	}
	if resp.Data.AccessToken != "access-tok" {
		t.Errorf("AccessToken: want %q, got %q", "access-tok", resp.Data.AccessToken)
	}
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	h := newHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestLoginHandler_ValidationError_MissingFields(t *testing.T) {
	h := newHandler(nil)

	req := makeJSONRequest(t, http.MethodPost, "/auth/login", map[string]any{})
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if len(resp.Errors) == 0 {
		t.Error("expected validation errors, got none")
	}
}

func TestLoginHandler_ValidationError_PasswordTooShort(t *testing.T) {
	h := newHandler(nil)

	req := makeJSONRequest(t, http.MethodPost, "/auth/login", map[string]any{
		"username": "user",
		"password": "short",
	})
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if _, ok := resp.Errors["password"]; !ok {
		t.Error("expected validation error for 'password'")
	}
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginFn: func(_, _ string, _ bool) (*services.TokenResponse, error) {
			return nil, services.ErrInvalidCredentials
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/login", map[string]any{
		"username": "user",
		"password": "password123",
	})
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: want %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestLoginHandler_InternalServerError(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginFn: func(_, _ string, _ bool) (*services.TokenResponse, error) {
			return nil, errors.New("unexpected db error")
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/login", map[string]any{
		"username": "user",
		"password": "password123",
	})
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status: want %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Register handler tests
// ---------------------------------------------------------------------------

var validRegisterBody = map[string]any{
	"firstName":      "John",
	"lastName":       "Doe",
	"username":       "johndoe",
	"email":          "john@example.com",
	"password":       "password123",
	"repeatPassword": "password123",
}

func TestRegisterHandler_Success(t *testing.T) {
	h := newHandler(&mockTokenService{
		registerFn: func(_, _, _, _, _ string) (*services.TokenResponse, error) {
			return tokenServiceResponse, nil
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/register", validRegisterBody)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status: want %d, got %d", http.StatusCreated, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Data == nil {
		t.Fatal("expected Data in response, got nil")
	}
}

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	h := newHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("{bad"))
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRegisterHandler_ValidationError_MissingFields(t *testing.T) {
	h := newHandler(nil)

	req := makeJSONRequest(t, http.MethodPost, "/auth/register", map[string]any{})
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if len(resp.Errors) == 0 {
		t.Error("expected validation errors")
	}
}

func TestRegisterHandler_ValidationError_InvalidEmail(t *testing.T) {
	h := newHandler(nil)

	body := map[string]any{
		"firstName":      "John",
		"lastName":       "Doe",
		"username":       "johndoe",
		"email":          "not-an-email",
		"password":       "password123",
		"repeatPassword": "password123",
	}
	req := makeJSONRequest(t, http.MethodPost, "/auth/register", body)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if _, ok := resp.Errors["email"]; !ok {
		t.Error("expected validation error for 'email'")
	}
}

func TestRegisterHandler_PasswordsDoNotMatch(t *testing.T) {
	h := newHandler(nil)

	body := map[string]any{
		"firstName":      "John",
		"lastName":       "Doe",
		"username":       "johndoe",
		"email":          "john@example.com",
		"password":       "password123",
		"repeatPassword": "different456",
	}
	req := makeJSONRequest(t, http.MethodPost, "/auth/register", body)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Message != "passwords do not match" {
		t.Errorf("message: want %q, got %q", "passwords do not match", resp.Message)
	}
}

func TestRegisterHandler_UserAlreadyExists(t *testing.T) {
	h := newHandler(&mockTokenService{
		registerFn: func(_, _, _, _, _ string) (*services.TokenResponse, error) {
			return nil, services.ErrUserAlreadyExists
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/register", validRegisterBody)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status: want %d, got %d", http.StatusConflict, rr.Code)
	}
}

func TestRegisterHandler_InternalServerError(t *testing.T) {
	h := newHandler(&mockTokenService{
		registerFn: func(_, _, _, _, _ string) (*services.TokenResponse, error) {
			return nil, errors.New("db down")
		},
	})

	req := makeJSONRequest(t, http.MethodPost, "/auth/register", validRegisterBody)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status: want %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Refresh handler tests
// ---------------------------------------------------------------------------

func TestRefreshHandler_Success(t *testing.T) {
	h := newHandler(&mockTokenService{
		refreshTokenFn: func(_ string) (*services.TokenResponse, error) {
			return tokenServiceResponse, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("X-Refresh-Token", "old-refresh-tok")
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want %d, got %d", http.StatusOK, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Data == nil {
		t.Fatal("expected Data in response, got nil")
	}
}

func TestRefreshHandler_MissingHeader(t *testing.T) {
	h := newHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRefreshHandler_ServiceError(t *testing.T) {
	h := newHandler(&mockTokenService{
		refreshTokenFn: func(_ string) (*services.TokenResponse, error) {
			return nil, errors.New("token expired")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("X-Refresh-Token", "expired")
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: want %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// ---------------------------------------------------------------------------
// LoginWithGoogle handler tests
// ---------------------------------------------------------------------------

func TestLoginWithGoogleHandler_Success(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginWithGoogleFn: func(_ string) (*services.TokenResponse, error) {
			return tokenServiceResponse, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/public/auth/login/google?googleToken=valid-token", nil)
	rr := httptest.NewRecorder()
	h.LoginWithGoogle(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want %d, got %d", http.StatusOK, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Data == nil {
		t.Fatal("expected Data in response")
	}
}

func TestLoginWithGoogleHandler_MissingQueryParam(t *testing.T) {
	h := newHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/public/auth/login/google", nil)
	rr := httptest.NewRecorder()
	h.LoginWithGoogle(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestLoginWithGoogleHandler_InvalidGoogleToken(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginWithGoogleFn: func(_ string) (*services.TokenResponse, error) {
			return nil, services.ErrInvalidGoogleToken
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/public/auth/login/google?googleToken=bad", nil)
	rr := httptest.NewRecorder()
	h.LoginWithGoogle(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: want %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestLoginWithGoogleHandler_InternalServerError(t *testing.T) {
	h := newHandler(&mockTokenService{
		loginWithGoogleFn: func(_ string) (*services.TokenResponse, error) {
			return nil, errors.New("unexpected error")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/public/auth/login/google?googleToken=tok", nil)
	rr := httptest.NewRecorder()
	h.LoginWithGoogle(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status: want %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Logout handler tests
// ---------------------------------------------------------------------------

func TestLogoutHandler_Success(t *testing.T) {
	h := newHandler(&mockTokenService{
		logoutFn: func(_ string) error { return nil },
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("X-Refresh-Token", "refresh-tok")
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want %d, got %d", http.StatusOK, rr.Code)
	}
	resp := decodeBody(t, rr.Body)
	if resp.Message != "logged out successfully" {
		t.Errorf("message: want %q, got %q", "logged out successfully", resp.Message)
	}
}

func TestLogoutHandler_MissingHeader(t *testing.T) {
	h := newHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestLogoutHandler_ServiceError(t *testing.T) {
	h := newHandler(&mockTokenService{
		logoutFn: func(_ string) error { return errors.New("token not found") },
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("X-Refresh-Token", "bad-tok")
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: want %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}
