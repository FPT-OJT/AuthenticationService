package adapters_repositories

import (
	"time"

	"authentication-service.com/internal/core/domain"
	"gorm.io/gorm"
)

type UserORM struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	Email     string
	Username  string `gorm:"column:user_name"`
	GoogleID  string
	Role      string `gorm:"default:'CUSTOMER'"`
	Password  string
	CreatedAt time.Time `gorm:"not null;autoCreateTime"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime"`
	DeletedAt gorm.DeletedAt
}

func (UserORM) TableName() string {
	return "users"
}

func (orm *UserORM) ToDomain() *domain.User {
	return &domain.User{
		ID:       orm.ID,
		Email:    orm.Email,
		Username: orm.Username,
		GoogleID: orm.GoogleID,
		Role:     orm.Role,
		Password: orm.Password,
	}
}

func FromDomain(user *domain.User) *UserORM {
	return &UserORM{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		GoogleID:  user.GoogleID,
		Role:      user.Role,
		Password:  user.Password,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
