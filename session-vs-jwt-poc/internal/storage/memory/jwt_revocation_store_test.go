package memory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestJWTRevocationStoreFindsAndForgetsRevocations(t *testing.T) {
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	store := NewJWTRevocationStore()
	store.now = func() time.Time { return now }

	if err := store.Revoke(context.Background(), "active-jti", now.Add(time.Minute)); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	revoked, err := store.IsRevoked(context.Background(), "active-jti")
	if err != nil || !revoked {
		t.Fatalf("IsRevoked() = %t, %v, want true, nil", revoked, err)
	}

	now = now.Add(time.Minute)
	revoked, err = store.IsRevoked(context.Background(), "active-jti")
	if err != nil || revoked {
		t.Fatalf("IsRevoked(expired) = %t, %v, want false, nil", revoked, err)
	}
	if len(store.revocations) != 0 {
		t.Fatalf("expired revocations retained = %d", len(store.revocations))
	}

	if err := store.Revoke(context.Background(), "already-expired", now); err != nil {
		t.Fatalf("Revoke(expired) error = %v", err)
	}
	if len(store.revocations) != 0 {
		t.Fatal("Revoke(expired) stored an entry")
	}
}

func TestJWTRevocationStoreConcurrentAccess(t *testing.T) {
	store := NewJWTRevocationStore()
	expiresAt := time.Now().Add(time.Minute)
	ctx := context.Background()

	var waitGroup sync.WaitGroup
	for index := 0; index < 100; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			credentialID := fmt.Sprintf("jti-%d", index)
			if err := store.Revoke(ctx, credentialID, expiresAt); err != nil {
				t.Errorf("Revoke(%s) error = %v", credentialID, err)
				return
			}
			if revoked, err := store.IsRevoked(ctx, credentialID); err != nil || !revoked {
				t.Errorf("IsRevoked(%s) = %t, %v", credentialID, revoked, err)
			}
		}(index)
	}
	waitGroup.Wait()
}
