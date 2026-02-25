package ports

import (
	"time"

	"authentication-service.com/internal/core/domain"
)

type RefreshTokenRepositoryPort interface {
	Save(token *domain.RefreshToken, ttl time.Duration) error
	FindByRefreshToken(refreshToken string) (*domain.RefreshToken, error)
	FindAllByFamilyToken(familyToken string) ([]*domain.RefreshToken, error)
	SaveAll(tokens []*domain.RefreshToken) error
	AtomicRevoke(refreshToken string) (int64, error)
}
