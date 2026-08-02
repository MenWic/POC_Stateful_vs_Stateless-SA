package redis

import (
	"context"
	"fmt"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

const jwtRevocationKeyPrefix = "poc:jwt-revoked:"

type JWTRevocationStore struct {
	client *redisclient.Client
}

func NewJWTRevocationStore(client *redisclient.Client) *JWTRevocationStore {
	return &JWTRevocationStore{client: client}
}

func (store *JWTRevocationStore) IsRevoked(ctx context.Context, credentialID string) (bool, error) {
	exists, err := store.client.Exists(ctx, jwtRevocationKey(credentialID)).Result()
	if err != nil {
		return false, fmt.Errorf("consultar revocación JWT en Redis: %w", err)
	}
	return exists > 0, nil
}

func (store *JWTRevocationStore) Revoke(ctx context.Context, credentialID string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	if err := store.client.Set(ctx, jwtRevocationKey(credentialID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("guardar revocación JWT en Redis: %w", err)
	}
	return nil
}

func jwtRevocationKey(credentialID string) string {
	return jwtRevocationKeyPrefix + credentialID
}
