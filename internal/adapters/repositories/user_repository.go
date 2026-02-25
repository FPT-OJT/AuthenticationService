package adapters_repositories

import (
	"errors"

	"authentication-service.com/internal/core/domain"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByUsernameOrEmail(usernameOrEmail string) (*domain.User, error) {
	var orm UserORM
	result := r.db.Where("user_name = ? OR email = ?", usernameOrEmail, usernameOrEmail).First(&orm)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, result.Error
	}
	return orm.ToDomain(), nil
}

func (r *UserRepository) FindByID(id string) (*domain.User, error) {
	var orm UserORM
	result := r.db.Where("id = ?", id).First(&orm)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, result.Error
	}
	return orm.ToDomain(), nil
}
