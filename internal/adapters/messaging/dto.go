package messaging

import "authentication-service.com/internal/core/domain"

type NewUserMessage struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

func FromEvent(event domain.UserCreatedEvent) *NewUserMessage {
	return &NewUserMessage{
		FirstName: event.FirstName,
		LastName:  event.LastName,
		Email:     event.Email,
	}
}
