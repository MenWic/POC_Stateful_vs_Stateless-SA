package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"session-vs-jwt-poc/internal/auth/session"
)

const (
	sessionKeyPrefix    = "poc:session:"
	userSessionsKeyBase = "poc:user-sessions:"
)

type SessionStore struct {
	client *redisclient.Client
}

func NewSessionStore(client *redisclient.Client) *SessionStore {
	return &SessionStore{client: client}
}

func (store *SessionStore) Save(ctx context.Context, currentSession session.Session) error {
	serializedSession, err := json.Marshal(currentSession)
	if err != nil {
		return fmt.Errorf("serializar sesión: %w", err)
	}

	ttl := time.Until(currentSession.AbsoluteExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("guardar sesión: la expiración absoluta ya ocurrió")
	}

	_, err = store.client.TxPipelined(ctx, func(pipeline redisclient.Pipeliner) error {
		indexKey := userSessionsKey(currentSession.UserID)
		pipeline.Set(ctx, sessionKey(currentSession.ID), serializedSession, ttl)
		pipeline.SAdd(ctx, indexKey, currentSession.ID)
		// NX establece la expiración inicial y GT solo la amplía cuando el nuevo límite es posterior
		pipeline.Do(ctx, "pexpireat", indexKey, currentSession.AbsoluteExpiresAt.UnixMilli(), "NX")
		pipeline.Do(ctx, "pexpireat", indexKey, currentSession.AbsoluteExpiresAt.UnixMilli(), "GT")
		return nil
	})
	if err != nil {
		return fmt.Errorf("guardar sesión e índice en Redis: %w", err)
	}

	return nil
}

func (store *SessionStore) Get(ctx context.Context, sessionID string) (session.Session, error) {
	serializedSession, err := store.client.Get(ctx, sessionKey(sessionID)).Bytes()
	if errors.Is(err, redisclient.Nil) {
		return session.Session{}, session.ErrNotFound
	}
	if err != nil {
		return session.Session{}, fmt.Errorf("leer sesión de Redis: %w", err)
	}

	currentSession, err := decodeSession(serializedSession)
	if err != nil {
		return session.Session{}, err
	}

	return currentSession, nil
}

func (store *SessionStore) UpdateActivity(ctx context.Context, sessionID string, lastSeenAt, idleExpiresAt time.Time) (session.Session, error) {
	currentSession, err := store.Get(ctx, sessionID)
	if err != nil {
		return session.Session{}, err
	}
	currentSession.LastSeenAt = lastSeenAt
	currentSession.IdleExpiresAt = idleExpiresAt

	serializedSession, err := json.Marshal(currentSession)
	if err != nil {
		return session.Session{}, fmt.Errorf("serializar actividad de sesión: %w", err)
	}
	ttl := time.Until(currentSession.AbsoluteExpiresAt)
	if ttl <= 0 {
		if err := store.Delete(ctx, sessionID); err != nil {
			return session.Session{}, err
		}
		return session.Session{}, session.ErrNotFound
	}

	updated, err := store.client.SetXX(ctx, sessionKey(sessionID), serializedSession, ttl).Result()
	if err != nil {
		return session.Session{}, fmt.Errorf("actualizar actividad en Redis: %w", err)
	}
	if !updated {
		return session.Session{}, session.ErrNotFound
	}

	return currentSession, nil
}

func (store *SessionStore) Delete(ctx context.Context, sessionID string) error {
	currentSession, err := store.Get(ctx, sessionID)
	if errors.Is(err, session.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	_, err = store.client.TxPipelined(ctx, func(pipeline redisclient.Pipeliner) error {
		pipeline.Del(ctx, sessionKey(sessionID))
		pipeline.SRem(ctx, userSessionsKey(currentSession.UserID), sessionID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("eliminar sesión e índice de Redis: %w", err)
	}

	return nil
}

func (store *SessionStore) DeleteByUserID(ctx context.Context, userID int64) error {
	indexKey := userSessionsKey(userID)
	sessionIDs, err := store.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return fmt.Errorf("leer índice de sesiones en Redis: %w", err)
	}

	_, err = store.client.TxPipelined(ctx, func(pipeline redisclient.Pipeliner) error {
		for _, sessionID := range sessionIDs {
			pipeline.Del(ctx, sessionKey(sessionID))
		}
		pipeline.Del(ctx, indexKey)
		return nil
	})
	if err != nil {
		return fmt.Errorf("eliminar sesiones del usuario en Redis: %w", err)
	}

	return nil
}

func decodeSession(serializedSession []byte) (session.Session, error) {
	var currentSession session.Session
	if err := json.Unmarshal(serializedSession, &currentSession); err != nil {
		return session.Session{}, fmt.Errorf("decodificar sesión de Redis: %w", err)
	}
	if currentSession.ID == "" || currentSession.UserID < 1 || currentSession.AbsoluteExpiresAt.IsZero() {
		return session.Session{}, fmt.Errorf("decodificar sesión de Redis: datos incompletos")
	}
	return currentSession, nil
}

func sessionKey(sessionID string) string {
	return sessionKeyPrefix + sessionID
}

func userSessionsKey(userID int64) string {
	return userSessionsKeyBase + strconv.FormatInt(userID, 10)
}

var _ session.Store = (*SessionStore)(nil)
