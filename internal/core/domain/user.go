package domain

import "errors"

var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID       string
	Username string
	Email    string
	GoogleID string
	Role     string
	Password string
}
