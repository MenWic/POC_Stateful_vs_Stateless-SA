package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/security"
	"session-vs-jwt-poc/internal/user"
)

const sessionIDBytes = 32

type UserReader interface {
	GetByID(ctx context.Context, userID int64) (user.Summary, error)
}

type Manager struct {
	store           Store
	users           UserReader
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	instanceID      string
	now             func() time.Time
}

func NewManager(store Store, users UserReader, idleTimeout, absoluteTimeout time.Duration, instanceID string) *Manager {
	return &Manager{
		store:           store,
		users:           users,
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
		instanceID:      instanceID,
		now:             time.Now,
	}
}

func (manager *Manager) Issue(ctx context.Context, credentials user.ValidatedCredentials) (auth.IssuedCredential, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return auth.IssuedCredential{}, err
	}
	csrfToken, err := security.GenerateCSRFToken()
	if err != nil {
		return auth.IssuedCredential{}, err
	}

	now := manager.now().UTC()
	absoluteExpiresAt := now.Add(manager.absoluteTimeout)
	idleExpiresAt := earlierTime(now.Add(manager.idleTimeout), absoluteExpiresAt)
	currentSession := Session{
		ID:                sessionID,
		UserID:            credentials.UserID,
		AuthVersion:       credentials.AuthVersion,
		CSRFToken:         csrfToken,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
	}
	if err := manager.store.Save(ctx, currentSession); err != nil {
		return auth.IssuedCredential{}, fmt.Errorf("guardar sesión: %w", err)
	}

	return auth.IssuedCredential{
		Value:     currentSession.ID,
		ExpiresAt: currentSession.AbsoluteExpiresAt,
	}, nil
}

func (manager *Manager) Validate(ctx context.Context, credentialValue string) (auth.RequestAuthentication, error) {
	currentSession, err := manager.store.Get(ctx, credentialValue)
	if errors.Is(err, ErrNotFound) {
		return auth.RequestAuthentication{}, auth.ErrInvalidCredential
	}
	if err != nil {
		return auth.RequestAuthentication{}, fmt.Errorf("consultar sesión: %w", err)
	}

	now := manager.now().UTC()
	if !now.Before(currentSession.AbsoluteExpiresAt) {
		if err := manager.store.Delete(ctx, currentSession.ID); err != nil {
			return auth.RequestAuthentication{}, fmt.Errorf("eliminar sesión con expiración absoluta: %w", err)
		}
		return auth.RequestAuthentication{}, auth.ErrAbsoluteExpired
	}
	if !now.Before(currentSession.IdleExpiresAt) {
		if err := manager.store.Delete(ctx, currentSession.ID); err != nil {
			return auth.RequestAuthentication{}, fmt.Errorf("eliminar sesión inactiva: %w", err)
		}
		return auth.RequestAuthentication{}, auth.ErrIdleExpired
	}

	currentUser, err := manager.users.GetByID(ctx, currentSession.UserID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			if revokeErr := manager.store.DeleteByUserID(ctx, currentSession.UserID); revokeErr != nil {
				return auth.RequestAuthentication{}, fmt.Errorf("revocar sesiones de usuario inexistente: %w", revokeErr)
			}
			return auth.RequestAuthentication{}, auth.ErrUserUnavailable
		}
		return auth.RequestAuthentication{}, fmt.Errorf("consultar usuario de sesión: %w", err)
	}
	if !currentUser.Active {
		if err := manager.store.DeleteByUserID(ctx, currentSession.UserID); err != nil {
			return auth.RequestAuthentication{}, fmt.Errorf("revocar sesiones de usuario bloqueado: %w", err)
		}
		return auth.RequestAuthentication{}, auth.ErrUserUnavailable
	}
	if currentUser.AuthVersion != currentSession.AuthVersion {
		if err := manager.store.DeleteByUserID(ctx, currentSession.UserID); err != nil {
			return auth.RequestAuthentication{}, fmt.Errorf("revocar sesiones con versión anterior: %w", err)
		}
		return auth.RequestAuthentication{}, auth.ErrCredentialRevoked
	}

	idleExpiresAt := earlierTime(now.Add(manager.idleTimeout), currentSession.AbsoluteExpiresAt)
	currentSession, err = manager.store.UpdateActivity(ctx, currentSession.ID, now, idleExpiresAt)
	if errors.Is(err, ErrNotFound) {
		return auth.RequestAuthentication{}, auth.ErrInvalidCredential
	}
	if err != nil {
		return auth.RequestAuthentication{}, fmt.Errorf("actualizar actividad de sesión: %w", err)
	}

	return auth.RequestAuthentication{
		Identity: auth.Identity{
			UserID:               currentUser.ID,
			Name:                 currentUser.Name,
			Email:                currentUser.Email,
			Role:                 currentUser.Role,
			AuthVersion:          currentSession.AuthVersion,
			AuthenticatedAt:      currentSession.CreatedAt,
			ExpiresAt:            currentSession.AbsoluteExpiresAt,
			IdleExpiresAt:        currentSession.IdleExpiresAt,
			AuthenticationMethod: "session",
			CredentialID:         currentSession.ID,
			InstanceID:           manager.instanceID,
		},
		CSRFToken: currentSession.CSRFToken,
	}, nil
}

func (manager *Manager) Revoke(ctx context.Context, credentialValue string) error {
	if err := manager.store.Delete(ctx, credentialValue); err != nil {
		return fmt.Errorf("revocar sesión: %w", err)
	}
	return nil
}

func (manager *Manager) RevokeUser(ctx context.Context, userID int64) error {
	if err := manager.store.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("revocar sesiones del usuario: %w", err)
	}
	return nil
}

func generateSessionID() (string, error) {
	randomBytes := make([]byte, sessionIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generar identificador de sesión: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func earlierTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}
