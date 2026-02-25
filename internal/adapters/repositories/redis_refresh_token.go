package adapters_repositories

import (
	"authentication-service.com/internal/core/domain"
)

type RedisRefreshTokenDTO struct {
	RefreshToken string `json:"refresh_token"`
	FamilyToken  string `json:"family_token"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	IsRevoked    bool   `json:"is_revoked"`
}

func (dto *RedisRefreshTokenDTO) ToDomain() *domain.RefreshToken {
	return &domain.RefreshToken{
		RefreshToken: dto.RefreshToken,
		FamilyToken:  dto.FamilyToken,
		UserID:       dto.UserID,
		Role:         dto.Role,
		IsRevoked:    dto.IsRevoked,
	}
}

func FromDomainRefreshToken(token *domain.RefreshToken) *RedisRefreshTokenDTO {
	return &RedisRefreshTokenDTO{
		RefreshToken: token.RefreshToken,
		FamilyToken:  token.FamilyToken,
		UserID:       token.UserID,
		Role:         token.Role,
		IsRevoked:    token.IsRevoked,
	}
}
