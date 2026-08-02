package memory

import (
	"context"
	"sync"
	"time"
)

type JWTRevocationStore struct {
	mutex       sync.Mutex
	revocations map[string]time.Time
	now         func() time.Time
}

func NewJWTRevocationStore() *JWTRevocationStore {
	return &JWTRevocationStore{
		revocations: make(map[string]time.Time),
		now:         time.Now,
	}
}

func (store *JWTRevocationStore) IsRevoked(ctx context.Context, credentialID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	now := store.now().UTC()
	store.deleteExpired(now)
	expiresAt, exists := store.revocations[credentialID]
	return exists && now.Before(expiresAt), nil
}

func (store *JWTRevocationStore) Revoke(ctx context.Context, credentialID string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	now := store.now().UTC()
	store.deleteExpired(now)
	if !now.Before(expiresAt) {
		return nil
	}
	store.revocations[credentialID] = expiresAt.UTC()
	return nil
}

func (store *JWTRevocationStore) deleteExpired(now time.Time) {
	for credentialID, expiresAt := range store.revocations {
		if !now.Before(expiresAt) {
			delete(store.revocations, credentialID)
		}
	}
}
