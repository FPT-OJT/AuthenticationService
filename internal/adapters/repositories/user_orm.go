package adapters_repositories

import (
	"time"

	"authentication-service.com/internal/core/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserORM struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	Email     *string
	Username  *string `gorm:"column:user_name"`
	GoogleID  *string `gorm:"column:google_id"`
	Role      string  `gorm:"default:'CUSTOMER'"`
	Password  string
	CreatedAt time.Time `gorm:"not null;autoCreateTime"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime"`
	DeletedAt gorm.DeletedAt
}

func (u *UserORM) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	return nil
}

func (UserORM) TableName() string {
	return "users"
}

func (orm *UserORM) ToDomain() *domain.User {
	googleID := ""
	email := ""
	username := ""
	if orm.Email != nil {
		email = *orm.Email
	}
	if orm.Username != nil {
		username = *orm.Username
	}
	if orm.GoogleID != nil {
		googleID = *orm.GoogleID
	}
	return &domain.User{
		ID:       orm.ID,
		Email:    email,
		Username: username,
		GoogleID: googleID,
		Role:     orm.Role,
		Password: orm.Password,
	}
}

func FromDomain(user *domain.User) *UserORM {
	var googleID *string
	if user.GoogleID != "" {
		googleID = &user.GoogleID
	}
	var email *string
	if user.Email != "" {
		email = &user.Email
	}
	var username *string
	if user.Username != "" {
		username = &user.Username
	}
	return &UserORM{
		ID:       user.ID,
		Email:    email,
		Username: username,
		GoogleID: googleID,
		Role:     user.Role,
		Password: user.Password,
	}
}
