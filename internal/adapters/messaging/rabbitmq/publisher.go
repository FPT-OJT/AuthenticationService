package rabbitmq

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	messaging "authentication-service.com/internal/adapters/messaging"
	"authentication-service.com/internal/core/domain"
	"authentication-service.com/internal/core/ports"
)

type userEventPublisher struct {
	url            string
	exchange       string
	routingKey     string
	publishTimeout time.Duration
	conn           *amqp.Connection // stored to close before redial
	channel        *amqp.Channel
	connClosed     chan *amqp.Error
	chClosed       chan *amqp.Error
	mu             sync.RWMutex
	quit           chan struct{}
}

func NewUserEventPublisher(url, exchange, routingKey string, publishTimeout time.Duration) (ports.EventPublisherPort, error) {
	p := &userEventPublisher{
		url:            url,
		exchange:       exchange,
		routingKey:     routingKey,
		publishTimeout: publishTimeout,
		quit:           make(chan struct{}),
	}
	if err := p.dial(); err != nil {
		return nil, err
	}
	go p.runConnectionManager()
	return p, nil
}

// dial creates a fresh TCP connection and channel, registering NotifyClose on
// both under the write lock so no close event is ever missed.
func (p *userEventPublisher) dial() error {
	conn, err := amqp.Dial(p.url)
	if err != nil {
		return fmt.Errorf("rabbitmq: failed to dial: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("rabbitmq: failed to open channel: %w", err)
	}

	connClosed := make(chan *amqp.Error, 1)
	conn.NotifyClose(connClosed)

	chClosed := make(chan *amqp.Error, 1)
	ch.NotifyClose(chClosed)

	p.mu.Lock()
	p.conn = conn
	p.channel = ch
	p.connClosed = connClosed
	p.chClosed = chClosed
	p.mu.Unlock()

	return nil
}

// runConnectionManager is a single long-running goroutine with a flat for-loop.
// It waits for a close event, cleans up stale resources, then retries dial with
// exponential back-off — no mutual goroutine spawning.
func (p *userEventPublisher) runConnectionManager() {
	for {
		p.mu.RLock()
		connClosed := p.connClosed
		chClosed := p.chClosed
		p.mu.RUnlock()

		var amqpErr *amqp.Error
		select {
		case <-p.quit:
			return
		case amqpErr = <-connClosed:
			if amqpErr == nil {
				return // intentional via Close()
			}
			log.Printf("rabbitmq: connection closed (%v), reconnecting...", amqpErr)
		case amqpErr = <-chClosed:
			if amqpErr == nil {
				return // intentional via Close()
			}
			log.Printf("rabbitmq: channel closed (%v), reconnecting...", amqpErr)
		}

		// Mark unavailable and close the stale connection to prevent leak.
		p.mu.Lock()
		p.channel = nil
		if p.conn != nil && !p.conn.IsClosed() {
			p.conn.Close()
		}
		p.conn = nil
		p.mu.Unlock()

		backoff := 2 * time.Second
		for {
			select {
			case <-p.quit:
				return
			case <-time.After(backoff):
			}
			if err := p.dial(); err != nil {
				log.Printf("rabbitmq: reconnect failed (%v), retrying in %s...", err, backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			log.Println("rabbitmq: reconnected successfully")
			break
		}
	}
}

func (p *userEventPublisher) Close() error {
	close(p.quit) // unblocks runConnectionManager
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.channel != nil {
		p.channel.Close()
		p.channel = nil
	}
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	return nil
}

func (p *userEventPublisher) PublishUserCreated(ctx context.Context, event domain.UserCreatedEvent) error {
	body, err := json.Marshal(messaging.FromEvent(event))
	if err != nil {
		return fmt.Errorf("rabbitmq: failed to marshal UserCreatedEvent: %w", err)
	}

	p.mu.RLock()
	ch := p.channel
	p.mu.RUnlock()

	if ch == nil {
		return fmt.Errorf("rabbitmq: channel not available, recovery in progress")
	}

	ctx, cancel := context.WithTimeout(ctx, p.publishTimeout)
	defer cancel()

	if err := ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         body,
		Timestamp:    time.Now(),
	}); err != nil {
		return fmt.Errorf("rabbitmq: failed to publish UserCreatedEvent: %w", err)
	}

	return nil
}
