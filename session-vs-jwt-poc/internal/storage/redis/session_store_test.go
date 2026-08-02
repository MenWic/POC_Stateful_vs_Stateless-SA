package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"session-vs-jwt-poc/internal/auth/session"
)

func TestSessionStoreIntegration(t *testing.T) {
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR no está definido")
	}

	ctx := context.Background()
	client := redisclient.NewClient(&redisclient.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	store := NewSessionStore(client)
	userID := time.Now().UnixNano()
	now := time.Now().UTC()
	first := session.Session{
		ID:                fmt.Sprintf("integration-%d-a", userID),
		UserID:            userID,
		AuthVersion:       1,
		CSRFToken:         "csrf-a",
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(2 * time.Minute),
	}
	second := first
	second.ID = fmt.Sprintf("integration-%d-b", userID)
	second.CSRFToken = "csrf-b"
	t.Cleanup(func() { _ = store.DeleteByUserID(ctx, userID) })

	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}

	loaded, err := store.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded.ID != first.ID || loaded.UserID != first.UserID || loaded.CSRFToken != first.CSRFToken {
		t.Fatalf("Get() = %#v", loaded)
	}

	ttl, err := client.TTL(ctx, sessionKey(first.ID)).Result()
	if err != nil {
		t.Fatalf("TTL() error = %v", err)
	}
	if ttl <= 0 || ttl > 2*time.Minute {
		t.Fatalf("TTL() = %v, want (0, 2m]", ttl)
	}

	newLastSeen := now.Add(10 * time.Second)
	newIdleExpiry := now.Add(70 * time.Second)
	updated, err := store.UpdateActivity(ctx, first.ID, newLastSeen, newIdleExpiry)
	if err != nil {
		t.Fatalf("UpdateActivity() error = %v", err)
	}
	if !updated.LastSeenAt.Equal(newLastSeen) || !updated.IdleExpiresAt.Equal(newIdleExpiry) || !updated.AbsoluteExpiresAt.Equal(first.AbsoluteExpiresAt) {
		t.Fatalf("UpdateActivity() = %#v", updated)
	}

	if err := store.Delete(ctx, first.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(ctx, first.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v, want ErrNotFound", err)
	}

	if err := store.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID() error = %v", err)
	}
	if _, err := store.Get(ctx, second.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Get(revoked) error = %v, want ErrNotFound", err)
	}
	exists, err := client.Exists(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		t.Fatalf("Exists(index) error = %v", err)
	}
	if exists != 0 {
		t.Fatalf("Exists(index) = %d, want 0", exists)
	}

	t.Run("farther expiration then nearer does not shrink index TTL", func(t *testing.T) {
		testIndexTTLOrder(t, store, client, ctx, now, true)
	})
	t.Run("nearer expiration then farther extends index TTL", func(t *testing.T) {
		testIndexTTLOrder(t, store, client, ctx, now, false)
	})
}

func testIndexTTLOrder(t *testing.T, store *SessionStore, client *redisclient.Client, ctx context.Context, now time.Time, fartherFirst bool) {
	t.Helper()

	userID := time.Now().UnixNano()
	nearer := session.Session{
		ID:                fmt.Sprintf("integration-%d-nearer", userID),
		UserID:            userID,
		AuthVersion:       1,
		CSRFToken:         "csrf-nearer",
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(2 * time.Minute),
	}
	farther := nearer
	farther.ID = fmt.Sprintf("integration-%d-farther", userID)
	farther.CSRFToken = "csrf-farther"
	farther.AbsoluteExpiresAt = now.Add(4 * time.Minute)

	first, second := nearer, farther
	if fartherFirst {
		first, second = farther, nearer
	}

	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	firstTTL, err := client.PTTL(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		t.Fatalf("TTL(index after first) error = %v", err)
	}
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	secondTTL, err := client.PTTL(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		t.Fatalf("TTL(index after second) error = %v", err)
	}

	if fartherFirst {
		if secondTTL < firstTTL-2*time.Second {
			t.Fatalf("TTL(index) shrank from %v to %v after nearer expiration", firstTTL, secondTTL)
		}
	} else if secondTTL < firstTTL+time.Minute {
		t.Fatalf("TTL(index) did not extend from %v to %v after farther expiration", firstTTL, secondTTL)
	}

	if err := store.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID() error = %v", err)
	}
	for _, currentSession := range []session.Session{nearer, farther} {
		if _, err := store.Get(ctx, currentSession.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("Get(%s) error = %v, want ErrNotFound", currentSession.ID, err)
		}
	}
	exists, err := client.Exists(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		t.Fatalf("Exists(index) error = %v", err)
	}
	if exists != 0 {
		t.Fatalf("Exists(index) = %d, want 0", exists)
	}
}
