package ports

import "authentication-service.com/internal/core/domain"

type UserRepositoryPort interface {
	FindByUsernameOrEmail(usernameOrEmail string) (*domain.User, error)
	FindByID(id string) (*domain.User, error)
	FindByGoogleID(googleID string) (*domain.User, error)
	Create(user *domain.User) (*domain.User, error)
	Update(user *domain.User) (*domain.User, error)
	Delete(id string) error
}
