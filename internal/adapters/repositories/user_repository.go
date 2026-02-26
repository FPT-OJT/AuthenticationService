package adapters_repositories

import (
	"errors"

	"authentication-service.com/internal/core/domain"
	"github.com/jackc/pgx/v5/pgconn"
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

func (r *UserRepository) Create(user *domain.User) (*domain.User, error) {
	orm := FromDomain(user)

	result := r.db.Create(orm)
	if result.Error != nil {
		var pgErr *pgconn.PgError
		if errors.As(result.Error, &pgErr) && pgErr.Code == "23505" {
			return nil, domain.ErrUserAlreadyExists
		}
		return nil, result.Error
	}
	return orm.ToDomain(), nil
}

func (r *UserRepository) Delete(id string) error {
	result := r.db.Where("id = ?", id).Delete(&UserORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
