package adapters_repositories

import (
	"context"
	"errors"
	"time"

	_ "embed"

	"authentication-service.com/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

//go:embed revoke_token.lua
var revokeTokenLuaScript string

const (
	refreshTokenKeyPrefix  = "refresh_tokens:"
	familyTokenIndexPrefix = "refresh_tokens:family:"
)

type RedisRefreshTokenRepository struct {
	client       *redis.Client
	revokeScript *redis.Script
}

func NewRedisRefreshTokenRepository(client *redis.Client) *RedisRefreshTokenRepository {
	return &RedisRefreshTokenRepository{
		client:       client,
		revokeScript: redis.NewScript(revokeTokenLuaScript),
	}
}

func (r *RedisRefreshTokenRepository) Save(token *domain.RefreshToken, ttl time.Duration) error {
	ctx := context.Background()

	key := refreshTokenKeyPrefix + token.RefreshToken
	familyKey := familyTokenIndexPrefix + token.FamilyToken

	isRevokedStr := "0"
	if token.IsRevoked {
		isRevokedStr = "1"
	}

	pipe := r.client.TxPipeline()

	pipe.HSet(ctx, key,
		"refresh_token", token.RefreshToken,
		"family_token", token.FamilyToken,
		"user_id", token.UserID,
		"role", token.Role,
		"is_revoked", isRevokedStr,
	)
	pipe.Expire(ctx, key, ttl)

	pipe.SAdd(ctx, familyKey, token.RefreshToken)
	pipe.Expire(ctx, familyKey, ttl)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRefreshTokenRepository) FindByRefreshToken(refreshToken string) (*domain.RefreshToken, error) {
	ctx := context.Background()
	key := refreshTokenKeyPrefix + refreshToken

	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.New("refresh token not found or expired")
	}

	dto := &RedisRefreshTokenDTO{
		RefreshToken: result["refresh_token"],
		FamilyToken:  result["family_token"],
		UserID:       result["user_id"],
		Role:         result["role"],
		IsRevoked:    result["is_revoked"] == "1",
	}
	return dto.ToDomain(), nil
}

func (r *RedisRefreshTokenRepository) FindAllByFamilyToken(familyToken string) ([]*domain.RefreshToken, error) {
	ctx := context.Background()
	familyKey := familyTokenIndexPrefix + familyToken

	tokenStrings, err := r.client.SMembers(ctx, familyKey).Result()
	if err != nil {
		return nil, err
	}

	var tokens []*domain.RefreshToken
	for _, tokenStr := range tokenStrings {
		token, err := r.FindByRefreshToken(tokenStr)
		if err != nil {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (r *RedisRefreshTokenRepository) SaveAll(tokens []*domain.RefreshToken) error {
	ctx := context.Background()
	pipe := r.client.TxPipeline()

	for _, token := range tokens {
		key := refreshTokenKeyPrefix + token.RefreshToken
		isRevokedStr := "0"
		if token.IsRevoked {
			isRevokedStr = "1"
		}
		pipe.HSet(ctx, key, "is_revoked", isRevokedStr)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRefreshTokenRepository) AtomicRevoke(refreshToken string) (int64, error) {
	ctx := context.Background()
	key := refreshTokenKeyPrefix + refreshToken

	result, err := r.revokeScript.Run(ctx, r.client, []string{key}, "is_revoked", "0").Int64()
	if err != nil {
		return 0, err
	}
	return result, nil
}
