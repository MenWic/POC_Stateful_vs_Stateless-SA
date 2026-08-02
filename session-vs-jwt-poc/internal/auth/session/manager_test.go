package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

type testStore struct {
	mutex    sync.Mutex
	sessions map[string]Session
}

func newTestStore() *testStore {
	return &testStore{sessions: make(map[string]Session)}
}

func (store *testStore) Save(ctx context.Context, currentSession Session) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.sessions[currentSession.ID] = currentSession
	return nil
}

func (store *testStore) Get(ctx context.Context, sessionID string) (Session, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	currentSession, exists := store.sessions[sessionID]
	if !exists {
		return Session{}, ErrNotFound
	}
	return currentSession, nil
}

func (store *testStore) UpdateActivity(ctx context.Context, sessionID string, lastSeenAt, idleExpiresAt time.Time) (Session, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	currentSession, exists := store.sessions[sessionID]
	if !exists {
		return Session{}, ErrNotFound
	}
	currentSession.LastSeenAt = lastSeenAt
	currentSession.IdleExpiresAt = idleExpiresAt
	store.sessions[sessionID] = currentSession
	return currentSession, nil
}

func (store *testStore) Delete(ctx context.Context, sessionID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	delete(store.sessions, sessionID)
	return nil
}

func (store *testStore) DeleteByUserID(ctx context.Context, userID int64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for sessionID, currentSession := range store.sessions {
		if currentSession.UserID == userID {
			delete(store.sessions, sessionID)
		}
	}
	return nil
}

type testUserReader struct {
	currentUser user.Summary
}

func (reader *testUserReader) GetByID(ctx context.Context, userID int64) (user.Summary, error) {
	if reader.currentUser.ID != userID {
		return user.Summary{}, user.ErrNotFound
	}
	return reader.currentUser, nil
}

func TestManagerUsesSlidingIdleTimeoutWithoutExtendingAbsoluteTimeout(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	users := &testUserReader{currentUser: user.Summary{
		ID: 1, Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, Active: true, AuthVersion: 1,
	}}
	manager := NewManager(store, users, 3*time.Minute, 10*time.Minute, "session-test")
	currentTime := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return currentTime }

	credentials := user.ValidatedCredentials{UserID: 1, Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, AuthVersion: 1}
	firstCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() first error = %v", err)
	}
	secondCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() second error = %v", err)
	}
	if firstCredential.Value == secondCredential.Value {
		t.Fatal("Issue() reused the session ID")
	}

	for _, elapsed := range []time.Duration{2 * time.Minute, 4 * time.Minute, 6 * time.Minute, 8 * time.Minute, 9*time.Minute + 30*time.Second} {
		currentTime = time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC).Add(elapsed)
		requestAuthentication, err := manager.Validate(ctx, firstCredential.Value)
		if err != nil {
			t.Fatalf("Validate() at %s error = %v", elapsed, err)
		}
		if requestAuthentication.Identity.IdleExpiresAt.After(firstCredential.ExpiresAt) {
			t.Fatal("Validate() extended idle expiration beyond absolute expiration")
		}
	}

	currentTime = firstCredential.ExpiresAt
	if _, err := manager.Validate(ctx, firstCredential.Value); !errors.Is(err, auth.ErrAbsoluteExpired) {
		t.Fatalf("Validate() absolute expiration error = %v", err)
	}
}

func TestManagerRejectsIdleExpirationAndRevokesUserSessions(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	users := &testUserReader{currentUser: user.Summary{
		ID: 7, Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, Active: true, AuthVersion: 1,
	}}
	manager := NewManager(store, users, time.Minute, 10*time.Minute, "session-test")
	currentTime := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return currentTime }
	credentials := user.ValidatedCredentials{UserID: 7, AuthVersion: 1}

	idleCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() idle error = %v", err)
	}
	currentTime = currentTime.Add(time.Minute)
	if _, err := manager.Validate(ctx, idleCredential.Value); !errors.Is(err, auth.ErrIdleExpired) {
		t.Fatalf("Validate() idle expiration error = %v", err)
	}

	currentTime = currentTime.Add(time.Second)
	firstCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() first revocation error = %v", err)
	}
	secondCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() second revocation error = %v", err)
	}
	if err := manager.RevokeUser(ctx, 7); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	for _, credential := range []auth.IssuedCredential{firstCredential, secondCredential} {
		if _, err := manager.Validate(ctx, credential.Value); !errors.Is(err, auth.ErrInvalidCredential) {
			t.Fatalf("Validate() revoked credential error = %v", err)
		}
	}
}

func TestManagerRejectsBlockedUserAndOldAuthVersion(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	users := &testUserReader{currentUser: user.Summary{
		ID: 9, Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, Active: true, AuthVersion: 1,
	}}
	manager := NewManager(store, users, time.Minute, 10*time.Minute, "session-test")
	manager.now = func() time.Time { return time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC) }
	credentials := user.ValidatedCredentials{UserID: 9, AuthVersion: 1}

	blockedCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() blocked error = %v", err)
	}
	users.currentUser.Active = false
	if _, err := manager.Validate(ctx, blockedCredential.Value); !errors.Is(err, auth.ErrUserUnavailable) {
		t.Fatalf("Validate() blocked user error = %v", err)
	}

	users.currentUser.Active = true
	users.currentUser.AuthVersion = 1
	oldCredential, err := manager.Issue(ctx, credentials)
	if err != nil {
		t.Fatalf("Issue() old version error = %v", err)
	}
	users.currentUser.AuthVersion = 2
	if _, err := manager.Validate(ctx, oldCredential.Value); !errors.Is(err, auth.ErrCredentialRevoked) {
		t.Fatalf("Validate() old auth version error = %v", err)
	}
}
