package google_verifier

import (
	"context"
	"fmt"

	"authentication-service.com/internal/core/ports"
	"google.golang.org/api/idtoken"
)

type googleTokenVerifier struct {
	clientID string
}

func NewGoogleTokenVerifier(clientID string) ports.GoogleTokenVerifierPort {
	return &googleTokenVerifier{clientID: clientID}
}

func (v *googleTokenVerifier) Verify(idTokenString string) (*ports.GoogleTokenPayload, error) {
	payload, err := idtoken.Validate(context.Background(), idTokenString, v.clientID)
	if err != nil {
		return nil, fmt.Errorf("google: invalid ID token: %w", err)
	}

	getString := func(key string) string {
		val, _ := payload.Claims[key].(string)
		return val
	}

	return &ports.GoogleTokenPayload{
		GoogleID:  payload.Subject,
		Email:     getString("email"),
		FirstName: getString("given_name"),
		LastName:  getString("family_name"),
	}, nil
}
