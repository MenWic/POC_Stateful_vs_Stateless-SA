package memory

import (
	"context"
	"sync"
	"time"

	"session-vs-jwt-poc/internal/auth/session"
)

type SessionStore struct {
	mutex        sync.RWMutex
	sessions     map[string]session.Session
	userSessions map[int64]map[string]struct{}
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:     make(map[string]session.Session),
		userSessions: make(map[int64]map[string]struct{}),
	}
}

func (store *SessionStore) Save(ctx context.Context, currentSession session.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	if previousSession, exists := store.sessions[currentSession.ID]; exists {
		store.removeFromUserIndex(previousSession.UserID, previousSession.ID)
	}
	store.sessions[currentSession.ID] = currentSession
	if _, exists := store.userSessions[currentSession.UserID]; !exists {
		store.userSessions[currentSession.UserID] = make(map[string]struct{})
	}
	store.userSessions[currentSession.UserID][currentSession.ID] = struct{}{}

	return nil
}

func (store *SessionStore) Get(ctx context.Context, sessionID string) (session.Session, error) {
	if err := ctx.Err(); err != nil {
		return session.Session{}, err
	}

	store.mutex.RLock()
	defer store.mutex.RUnlock()

	currentSession, exists := store.sessions[sessionID]
	if !exists {
		return session.Session{}, session.ErrNotFound
	}

	return currentSession, nil
}

func (store *SessionStore) UpdateActivity(ctx context.Context, sessionID string, lastSeenAt, idleExpiresAt time.Time) (session.Session, error) {
	if err := ctx.Err(); err != nil {
		return session.Session{}, err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	currentSession, exists := store.sessions[sessionID]
	if !exists {
		return session.Session{}, session.ErrNotFound
	}
	currentSession.LastSeenAt = lastSeenAt
	currentSession.IdleExpiresAt = idleExpiresAt
	store.sessions[sessionID] = currentSession

	return currentSession, nil
}

func (store *SessionStore) Delete(ctx context.Context, sessionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	currentSession, exists := store.sessions[sessionID]
	if !exists {
		return nil
	}
	delete(store.sessions, sessionID)
	store.removeFromUserIndex(currentSession.UserID, sessionID)

	return nil
}

func (store *SessionStore) DeleteByUserID(ctx context.Context, userID int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	for sessionID := range store.userSessions[userID] {
		delete(store.sessions, sessionID)
	}
	delete(store.userSessions, userID)

	return nil
}

func (store *SessionStore) removeFromUserIndex(userID int64, sessionID string) {
	indexedSessions, exists := store.userSessions[userID]
	if !exists {
		return
	}
	delete(indexedSessions, sessionID)
	if len(indexedSessions) == 0 {
		delete(store.userSessions, userID)
	}
}
