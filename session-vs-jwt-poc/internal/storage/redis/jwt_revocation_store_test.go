package redis

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

func TestJWTRevocationStoreIntegration(t *testing.T) {
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR no está definido")
	}

	ctx := context.Background()
	firstClient := redisclient.NewClient(&redisclient.Options{Addr: address})
	secondClient := redisclient.NewClient(&redisclient.Options{Addr: address})
	t.Cleanup(func() { _ = firstClient.Close() })
	t.Cleanup(func() { _ = secondClient.Close() })
	if err := firstClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	credentialID := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	expiredCredentialID := credentialID + "-expired"
	t.Cleanup(func() {
		_ = firstClient.Del(ctx, jwtRevocationKey(credentialID), jwtRevocationKey(expiredCredentialID)).Err()
	})

	firstStore := NewJWTRevocationStore(firstClient)
	secondStore := NewJWTRevocationStore(secondClient)
	expiresAt := time.Now().Add(2 * time.Minute)
	if err := firstStore.Revoke(ctx, credentialID, expiresAt); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	revoked, err := secondStore.IsRevoked(ctx, credentialID)
	if err != nil || !revoked {
		t.Fatalf("IsRevoked(second store) = %t, %v, want true, nil", revoked, err)
	}
	ttl, err := firstClient.PTTL(ctx, jwtRevocationKey(credentialID)).Result()
	if err != nil {
		t.Fatalf("PTTL() error = %v", err)
	}
	if ttl <= 0 || ttl > 2*time.Minute {
		t.Fatalf("PTTL() = %v, want (0, 2m]", ttl)
	}

	if err := firstStore.Revoke(ctx, expiredCredentialID, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Revoke(expired) error = %v", err)
	}
	exists, err := firstClient.Exists(ctx, jwtRevocationKey(expiredCredentialID)).Result()
	if err != nil {
		t.Fatalf("Exists(expired) error = %v", err)
	}
	if exists != 0 {
		t.Fatalf("Exists(expired) = %d, want 0", exists)
	}
}
