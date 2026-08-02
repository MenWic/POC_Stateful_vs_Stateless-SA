package session

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("sesión no encontrada")

type Session struct {
	ID                string
	UserID            int64
	AuthVersion       int64
	CSRFToken         string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type Store interface {
	Save(ctx context.Context, currentSession Session) error
	Get(ctx context.Context, sessionID string) (Session, error)
	UpdateActivity(ctx context.Context, sessionID string, lastSeenAt, idleExpiresAt time.Time) (Session, error)
	Delete(ctx context.Context, sessionID string) error
	DeleteByUserID(ctx context.Context, userID int64) error
}
