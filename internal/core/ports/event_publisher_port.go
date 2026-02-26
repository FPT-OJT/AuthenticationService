package ports

import (
	"context"

	"authentication-service.com/internal/core/domain"
)

type EventPublisherPort interface {
	PublishUserCreated(ctx context.Context, event domain.UserCreatedEvent) error
	Close() error
}
