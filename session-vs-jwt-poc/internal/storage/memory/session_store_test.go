package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth/session"
)

func TestSessionStoreConcurrentAccessAndUserRevocation(t *testing.T) {
	store := NewSessionStore()
	ctx := context.Background()
	now := time.Now().UTC()

	var waitGroup sync.WaitGroup
	for index := 0; index < 100; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			sessionID := fmt.Sprintf("session-%d", index)
			currentSession := session.Session{
				ID:                sessionID,
				UserID:            42,
				CreatedAt:         now,
				LastSeenAt:        now,
				IdleExpiresAt:     now.Add(time.Minute),
				AbsoluteExpiresAt: now.Add(10 * time.Minute),
			}
			if err := store.Save(ctx, currentSession); err != nil {
				t.Errorf("Save() error = %v", err)
				return
			}
			if _, err := store.Get(ctx, sessionID); err != nil {
				t.Errorf("Get() error = %v", err)
				return
			}
			if _, err := store.UpdateActivity(ctx, sessionID, now.Add(time.Second), now.Add(2*time.Minute)); err != nil {
				t.Errorf("UpdateActivity() error = %v", err)
			}
		}(index)
	}
	waitGroup.Wait()

	if err := store.DeleteByUserID(ctx, 42); err != nil {
		t.Fatalf("DeleteByUserID() error = %v", err)
	}
	for index := 0; index < 100; index++ {
		_, err := store.Get(ctx, fmt.Sprintf("session-%d", index))
		if !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("Get() after revocation error = %v", err)
		}
	}
}
