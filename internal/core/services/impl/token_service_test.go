package services_impl

import (
	"context"
	"errors"
	"testing"

	"authentication-service.com/internal/core/domain"
	"authentication-service.com/internal/core/ports"
	"authentication-service.com/internal/core/services"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Manual mocks
// ---------------------------------------------------------------------------

// mockUserRepo implements ports.UserRepositoryPort
type mockUserRepo struct {
	findByUsernameOrEmailFn func(string) (*domain.User, error)
	findByIDFn              func(string) (*domain.User, error)
	findByGoogleIDFn        func(string) (*domain.User, error)
	createFn                func(*domain.User) (*domain.User, error)
	updateFn                func(*domain.User) (*domain.User, error)
	deleteFn                func(string) error
}

func (m *mockUserRepo) FindByUsernameOrEmail(s string) (*domain.User, error) {
	return m.findByUsernameOrEmailFn(s)
}
func (m *mockUserRepo) FindByID(s string) (*domain.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(s)
	}
	return nil, domain.ErrUserNotFound
}
func (m *mockUserRepo) FindByGoogleID(s string) (*domain.User, error) {
	if m.findByGoogleIDFn != nil {
		return m.findByGoogleIDFn(s)
	}
	return nil, domain.ErrUserNotFound
}
func (m *mockUserRepo) Create(u *domain.User) (*domain.User, error) {
	if m.createFn != nil {
		return m.createFn(u)
	}
	return u, nil
}
func (m *mockUserRepo) Update(u *domain.User) (*domain.User, error) {
	if m.updateFn != nil {
		return m.updateFn(u)
	}
	return u, nil
}
func (m *mockUserRepo) Delete(s string) error {
	if m.deleteFn != nil {
		return m.deleteFn(s)
	}
	return nil
}

// mockTokenPort implements ports.TokenPort
type mockTokenPort struct {
	generateAccessTokenFn               func(string, string, string) (string, error)
	generateRefreshTokenFn              func(string, string, string, bool) (string, error)
	generateAccessTokenByRefreshTokenFn func(string) (*ports.AccessTokenData, error)
	validateTokenFn                     func(string) error
	extractClaimsFn                     func(string) (jwt.MapClaims, error)
	revokeByFamilyTokenFn               func(string) error
	revokeByRefreshTokenFn              func(string) error
}

func (m *mockTokenPort) GenerateAccessToken(userID, familyToken, role string) (string, error) {
	return m.generateAccessTokenFn(userID, familyToken, role)
}
func (m *mockTokenPort) GenerateRefreshToken(userID, familyToken, role string, rememberMe bool) (string, error) {
	return m.generateRefreshTokenFn(userID, familyToken, role, rememberMe)
}
func (m *mockTokenPort) GenerateAccessTokenByRefreshToken(refreshToken string) (*ports.AccessTokenData, error) {
	return m.generateAccessTokenByRefreshTokenFn(refreshToken)
}
func (m *mockTokenPort) ValidateToken(token string) error {
	if m.validateTokenFn != nil {
		return m.validateTokenFn(token)
	}
	return nil
}
func (m *mockTokenPort) ExtractClaims(token string) (jwt.MapClaims, error) {
	return m.extractClaimsFn(token)
}
func (m *mockTokenPort) RevokeByFamilyToken(familyToken string) error {
	if m.revokeByFamilyTokenFn != nil {
		return m.revokeByFamilyTokenFn(familyToken)
	}
	return nil
}
func (m *mockTokenPort) RevokeByRefreshToken(refreshToken string) error {
	return m.revokeByRefreshTokenFn(refreshToken)
}

// mockEventPublisher implements ports.EventPublisherPort
type mockEventPublisher struct {
	publishUserCreatedFn func(context.Context, domain.UserCreatedEvent) error
	closeFn              func() error
}

func (m *mockEventPublisher) PublishUserCreated(ctx context.Context, event domain.UserCreatedEvent) error {
	return m.publishUserCreatedFn(ctx, event)
}
func (m *mockEventPublisher) Close() error {
	if m.closeFn != nil {
		return m.closeFn()
	}
	return nil
}

// mockGoogleVerifier implements ports.GoogleTokenVerifierPort
type mockGoogleVerifier struct {
	verifyFn func(string) (*ports.GoogleTokenPayload, error)
}

func (m *mockGoogleVerifier) Verify(idToken string) (*ports.GoogleTokenPayload, error) {
	return m.verifyFn(idToken)
}

// ---------------------------------------------------------------------------
// Helper: build a TokenService wired with given mocks
// ---------------------------------------------------------------------------

func buildService(
	userRepo ports.UserRepositoryPort,
	tokenPort ports.TokenPort,
	publisher ports.EventPublisherPort,
	googleVerifier ports.GoogleTokenVerifierPort,
) *TokenService {
	return NewTokenService(userRepo, tokenPort, publisher, googleVerifier)
}

// hashedPwd returns a bcrypt hash of the given plain-text password.
func hashedPwd(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt failed: %v", err)
	}
	return string(h)
}

// familyTokenClaims returns a MapClaims with a "family_token" field.
func familyTokenClaims(family string) jwt.MapClaims {
	return jwt.MapClaims{"family_token": family}
}

// ---------------------------------------------------------------------------
// Login tests
// ---------------------------------------------------------------------------

func TestLogin_Success(t *testing.T) {
	hash := hashedPwd(t, "password123")
	user := &domain.User{ID: "user-1", Username: "testuser", Role: "CUSTOMER", Password: hash}

	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) { return user, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		nil,
		nil,
	)

	resp, err := svc.Login("testuser", "password123", false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != "access-tok" {
		t.Errorf("AccessToken: want %q, got %q", "access-tok", resp.AccessToken)
	}
	if resp.RefreshToken != "refresh-tok" {
		t.Errorf("RefreshToken: want %q, got %q", "refresh-tok", resp.RefreshToken)
	}
	if resp.UserID != user.ID {
		t.Errorf("UserID: want %q, got %q", user.ID, resp.UserID)
	}
	if resp.Role != user.Role {
		t.Errorf("Role: want %q, got %q", user.Role, resp.Role)
	}
}

func TestLogin_UserNotFound_ReturnsInvalidCredentials(t *testing.T) {
	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) {
				return nil, domain.ErrUserNotFound
			},
		},
		nil, nil, nil,
	)

	_, err := svc.Login("unknown", "password123", false)
	if !errors.Is(err, services.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_WrongPassword_ReturnsInvalidCredentials(t *testing.T) {
	hash := hashedPwd(t, "correct-password")
	user := &domain.User{ID: "user-1", Role: "CUSTOMER", Password: hash}

	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) { return user, nil },
		},
		nil, nil, nil,
	)

	_, err := svc.Login("testuser", "wrong-password", false)
	if !errors.Is(err, services.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_GenerateRefreshTokenError(t *testing.T) {
	hash := hashedPwd(t, "password123")
	user := &domain.User{ID: "user-1", Role: "CUSTOMER", Password: hash}
	tokenErr := errors.New("token gen failed")

	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) { return user, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "", tokenErr
			},
		},
		nil, nil,
	)

	_, err := svc.Login("testuser", "password123", false)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestLogin_ExtractClaimsError(t *testing.T) {
	hash := hashedPwd(t, "password123")
	user := &domain.User{ID: "user-1", Role: "CUSTOMER", Password: hash}
	claimsErr := errors.New("claims error")

	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) { return user, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return nil, claimsErr
			},
		},
		nil, nil,
	)

	_, err := svc.Login("testuser", "password123", false)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestLogin_RememberMe_PassedToTokenPort(t *testing.T) {
	hash := hashedPwd(t, "password123")
	user := &domain.User{ID: "user-1", Role: "CUSTOMER", Password: hash}
	var capturedRememberMe bool

	svc := buildService(
		&mockUserRepo{
			findByUsernameOrEmailFn: func(s string) (*domain.User, error) { return user, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, rememberMe bool) (string, error) {
				capturedRememberMe = rememberMe
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		nil, nil,
	)

	if _, err := svc.Login("testuser", "password123", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !capturedRememberMe {
		t.Error("expected rememberMe=true to be forwarded to GenerateRefreshToken")
	}
}

// ---------------------------------------------------------------------------
// Register tests
// ---------------------------------------------------------------------------

func TestRegister_Success(t *testing.T) {
	createdUser := &domain.User{ID: "new-user", Email: "john@example.com", Role: "CUSTOMER"}

	svc := buildService(
		&mockUserRepo{
			createFn: func(u *domain.User) (*domain.User, error) { return createdUser, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		&mockEventPublisher{
			publishUserCreatedFn: func(_ context.Context, _ domain.UserCreatedEvent) error {
				return nil
			},
		},
		nil,
	)

	resp, err := svc.Register("John", "Doe", "johndoe", "john@example.com", "password123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != "access-tok" {
		t.Errorf("AccessToken: want %q, got %q", "access-tok", resp.AccessToken)
	}
	if resp.UserID != createdUser.ID {
		t.Errorf("UserID: want %q, got %q", createdUser.ID, resp.UserID)
	}
}

func TestRegister_UserAlreadyExists(t *testing.T) {
	svc := buildService(
		&mockUserRepo{
			createFn: func(u *domain.User) (*domain.User, error) {
				return nil, domain.ErrUserAlreadyExists
			},
		},
		nil, nil, nil,
	)

	_, err := svc.Register("John", "Doe", "johndoe", "john@example.com", "password123")
	if !errors.Is(err, services.ErrUserAlreadyExists) {
		t.Errorf("expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestRegister_CreateRepoError(t *testing.T) {
	repoErr := errors.New("db connection lost")

	svc := buildService(
		&mockUserRepo{
			createFn: func(u *domain.User) (*domain.User, error) { return nil, repoErr },
		},
		nil, nil, nil,
	)

	_, err := svc.Register("John", "Doe", "johndoe", "john@example.com", "password123")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestRegister_EventPublishFailure(t *testing.T) {
	createdUser := &domain.User{ID: "new-user", Email: "john@example.com", Role: "CUSTOMER"}
	publishErr := errors.New("rabbitmq down")

	svc := buildService(
		&mockUserRepo{
			createFn: func(u *domain.User) (*domain.User, error) { return createdUser, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		&mockEventPublisher{
			publishUserCreatedFn: func(_ context.Context, _ domain.UserCreatedEvent) error {
				return publishErr
			},
		},
		nil,
	)

	_, err := svc.Register("John", "Doe", "johndoe", "john@example.com", "password123")
	if err == nil {
		t.Fatal("expected error from publish failure, got nil")
	}
}

func TestRegister_EventPublish_ReceivesCorrectData(t *testing.T) {
	createdUser := &domain.User{ID: "new-user", Email: "alice@example.com", Role: "CUSTOMER"}
	var capturedEvent domain.UserCreatedEvent

	svc := buildService(
		&mockUserRepo{
			createFn: func(u *domain.User) (*domain.User, error) { return createdUser, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		&mockEventPublisher{
			publishUserCreatedFn: func(_ context.Context, event domain.UserCreatedEvent) error {
				capturedEvent = event
				return nil
			},
		},
		nil,
	)

	_, _ = svc.Register("Alice", "Smith", "alice", "alice@example.com", "password123")

	if capturedEvent.FirstName != "Alice" {
		t.Errorf("FirstName: want %q, got %q", "Alice", capturedEvent.FirstName)
	}
	if capturedEvent.LastName != "Smith" {
		t.Errorf("LastName: want %q, got %q", "Smith", capturedEvent.LastName)
	}
	if capturedEvent.Email != createdUser.Email {
		t.Errorf("Email: want %q, got %q", createdUser.Email, capturedEvent.Email)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken tests
// ---------------------------------------------------------------------------

func TestRefreshToken_Success(t *testing.T) {
	data := &ports.AccessTokenData{
		AccessToken: "new-access-tok",
		UserID:      "user-1",
		Role:        "CUSTOMER",
		FamilyToken: "fam-1",
	}

	svc := buildService(
		nil,
		&mockTokenPort{
			generateAccessTokenByRefreshTokenFn: func(_ string) (*ports.AccessTokenData, error) {
				return data, nil
			},
		},
		nil, nil,
	)

	resp, err := svc.RefreshToken("old-refresh-tok")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken != data.AccessToken {
		t.Errorf("AccessToken: want %q, got %q", data.AccessToken, resp.AccessToken)
	}
	if resp.RefreshToken != "old-refresh-tok" {
		t.Errorf("RefreshToken: want %q, got %q", "old-refresh-tok", resp.RefreshToken)
	}
	if resp.UserID != data.UserID {
		t.Errorf("UserID: want %q, got %q", data.UserID, resp.UserID)
	}
}

func TestRefreshToken_Error(t *testing.T) {
	tokenErr := errors.New("token expired")

	svc := buildService(
		nil,
		&mockTokenPort{
			generateAccessTokenByRefreshTokenFn: func(_ string) (*ports.AccessTokenData, error) {
				return nil, tokenErr
			},
		},
		nil, nil,
	)

	_, err := svc.RefreshToken("bad-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Logout tests
// ---------------------------------------------------------------------------

func TestLogout_Success(t *testing.T) {
	svc := buildService(
		nil,
		&mockTokenPort{
			revokeByRefreshTokenFn: func(_ string) error { return nil },
		},
		nil, nil,
	)

	if err := svc.Logout("refresh-tok"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestLogout_Error(t *testing.T) {
	revokeErr := errors.New("token not found")

	svc := buildService(
		nil,
		&mockTokenPort{
			revokeByRefreshTokenFn: func(_ string) error { return revokeErr },
		},
		nil, nil,
	)

	if err := svc.Logout("bad-token"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoginWithGoogle tests
// ---------------------------------------------------------------------------

func TestLoginWithGoogle_InvalidToken(t *testing.T) {
	svc := buildService(
		nil, nil, nil,
		&mockGoogleVerifier{
			verifyFn: func(_ string) (*ports.GoogleTokenPayload, error) {
				return nil, errors.New("invalid google token")
			},
		},
	)

	_, err := svc.LoginWithGoogle("bad-google-token")
	if !errors.Is(err, services.ErrInvalidGoogleToken) {
		t.Errorf("expected ErrInvalidGoogleToken, got %v", err)
	}
}

func TestLoginWithGoogle_ExistingGoogleUser(t *testing.T) {
	existingUser := &domain.User{ID: "google-user-1", Email: "g@gmail.com", Role: "CUSTOMER", GoogleID: "g-id-1"}

	svc := buildService(
		&mockUserRepo{
			findByGoogleIDFn: func(_ string) (*domain.User, error) { return existingUser, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		nil,
		&mockGoogleVerifier{
			verifyFn: func(_ string) (*ports.GoogleTokenPayload, error) {
				return &ports.GoogleTokenPayload{GoogleID: "g-id-1", Email: "g@gmail.com"}, nil
			},
		},
	)

	resp, err := svc.LoginWithGoogle("valid-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.UserID != existingUser.ID {
		t.Errorf("UserID: want %q, got %q", existingUser.ID, resp.UserID)
	}
}

func TestLoginWithGoogle_ExistingEmailUser_LinksGoogleID(t *testing.T) {
	existingUser := &domain.User{ID: "email-user-1", Email: "g@gmail.com", Role: "CUSTOMER"}
	var updatedUser *domain.User

	svc := buildService(
		&mockUserRepo{
			findByGoogleIDFn: func(_ string) (*domain.User, error) {
				return nil, domain.ErrUserNotFound
			},
			findByUsernameOrEmailFn: func(_ string) (*domain.User, error) {
				return existingUser, nil
			},
			updateFn: func(u *domain.User) (*domain.User, error) {
				updatedUser = u
				return u, nil
			},
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		nil,
		&mockGoogleVerifier{
			verifyFn: func(_ string) (*ports.GoogleTokenPayload, error) {
				return &ports.GoogleTokenPayload{GoogleID: "new-g-id", Email: "g@gmail.com"}, nil
			},
		},
	)

	resp, err := svc.LoginWithGoogle("valid-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.UserID != existingUser.ID {
		t.Errorf("UserID: want %q, got %q", existingUser.ID, resp.UserID)
	}
	if updatedUser == nil || updatedUser.GoogleID != "new-g-id" {
		t.Error("expected GoogleID to be linked on existing user")
	}
}

func TestLoginWithGoogle_NewUser_Created(t *testing.T) {
	newUser := &domain.User{ID: "created-user-1", Email: "new@gmail.com", Role: "CUSTOMER", GoogleID: "g-id-new"}

	svc := buildService(
		&mockUserRepo{
			findByGoogleIDFn: func(_ string) (*domain.User, error) {
				return nil, domain.ErrUserNotFound
			},
			findByUsernameOrEmailFn: func(_ string) (*domain.User, error) {
				return nil, domain.ErrUserNotFound
			},
			createFn: func(u *domain.User) (*domain.User, error) {
				return newUser, nil
			},
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "refresh-tok", nil
			},
			extractClaimsFn: func(_ string) (jwt.MapClaims, error) {
				return familyTokenClaims("fam-1"), nil
			},
			generateAccessTokenFn: func(_, _, _ string) (string, error) {
				return "access-tok", nil
			},
		},
		nil,
		&mockGoogleVerifier{
			verifyFn: func(_ string) (*ports.GoogleTokenPayload, error) {
				return &ports.GoogleTokenPayload{GoogleID: "g-id-new", Email: "new@gmail.com"}, nil
			},
		},
	)

	resp, err := svc.LoginWithGoogle("valid-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.UserID != newUser.ID {
		t.Errorf("UserID: want %q, got %q", newUser.ID, resp.UserID)
	}
}

func TestLoginWithGoogle_TokenGenError(t *testing.T) {
	existingUser := &domain.User{ID: "user-1", Email: "g@gmail.com", Role: "CUSTOMER", GoogleID: "g-id-1"}
	tokenErr := errors.New("token gen failed")

	svc := buildService(
		&mockUserRepo{
			findByGoogleIDFn: func(_ string) (*domain.User, error) { return existingUser, nil },
		},
		&mockTokenPort{
			generateRefreshTokenFn: func(_, _, _ string, _ bool) (string, error) {
				return "", tokenErr
			},
		},
		nil,
		&mockGoogleVerifier{
			verifyFn: func(_ string) (*ports.GoogleTokenPayload, error) {
				return &ports.GoogleTokenPayload{GoogleID: "g-id-1", Email: "g@gmail.com"}, nil
			},
		},
	)

	_, err := svc.LoginWithGoogle("valid-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
