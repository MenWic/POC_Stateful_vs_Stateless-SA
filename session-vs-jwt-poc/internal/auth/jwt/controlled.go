package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

type RevocationStore interface {
	IsRevoked(ctx context.Context, credentialID string) (bool, error)
	Revoke(ctx context.Context, credentialID string, expiresAt time.Time) error
}

type UserReader interface {
	GetByID(ctx context.Context, userID int64) (user.Summary, error)
}

type ControlledAuthenticator struct {
	manager *Manager
	store   RevocationStore
	users   UserReader
}

func NewControlledAuthenticator(manager *Manager, store RevocationStore, users UserReader) *ControlledAuthenticator {
	return &ControlledAuthenticator{manager: manager, store: store, users: users}
}

func (authenticator *ControlledAuthenticator) Validate(ctx context.Context, credentialValue string) (auth.RequestAuthentication, error) {
	requestAuthentication, err := authenticator.manager.Validate(ctx, credentialValue)
	if err != nil {
		return auth.RequestAuthentication{}, err
	}

	identity := requestAuthentication.Identity
	revoked, err := authenticator.store.IsRevoked(ctx, identity.CredentialID)
	if err != nil {
		return auth.RequestAuthentication{}, fmt.Errorf("consultar denylist JWT: %w", err)
	}
	if revoked {
		return auth.RequestAuthentication{}, auth.ErrCredentialRevoked
	}

	currentUser, err := authenticator.users.GetByID(ctx, identity.UserID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return auth.RequestAuthentication{}, auth.ErrUserUnavailable
		}
		return auth.RequestAuthentication{}, fmt.Errorf("consultar usuario actual del JWT: %w", err)
	}
	if !currentUser.Active {
		return auth.RequestAuthentication{}, auth.ErrUserUnavailable
	}
	if currentUser.AuthVersion != identity.AuthVersion {
		return auth.RequestAuthentication{}, auth.ErrCredentialRevoked
	}

	identity.Name = currentUser.Name
	identity.Email = currentUser.Email
	identity.Role = currentUser.Role
	requestAuthentication.Identity = identity
	return requestAuthentication, nil
}

func (authenticator *ControlledAuthenticator) Revoke(ctx context.Context, credentialValue string) error {
	requestAuthentication, err := authenticator.manager.Validate(ctx, credentialValue)
	if err != nil {
		// Una credencial vieja o manipulada no debe impedir que login la reemplace ni que logout limpie cookies
		if errors.Is(err, auth.ErrCredentialExpired) || errors.Is(err, auth.ErrInvalidCredential) {
			return nil
		}
		return err
	}

	identity := requestAuthentication.Identity
	if err := authenticator.store.Revoke(ctx, identity.CredentialID, identity.ExpiresAt); err != nil {
		return fmt.Errorf("revocar JWT: %w", err)
	}
	return nil
}

func (*ControlledAuthenticator) RevokeUser(context.Context, int64) error {
	// Active y AuthVersion invalidan globalmente sin mantener un índice de JWT por usuario
	return nil
}
