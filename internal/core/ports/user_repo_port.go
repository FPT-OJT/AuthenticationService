package ports

import "authentication-service.com/internal/core/domain"

type UserRepositoryPort interface {
	FindByUsernameOrEmail(usernameOrEmail string) (*domain.User, error)
	FindByID(id string) (*domain.User, error)
}
