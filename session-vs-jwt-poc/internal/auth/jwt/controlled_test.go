package jwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

type controlledTestStore struct {
	revoked      bool
	err          error
	checks       int
	revokedID    string
	revokedUntil time.Time
	revokeCalls  int
}

func (store *controlledTestStore) IsRevoked(context.Context, string) (bool, error) {
	store.checks++
	return store.revoked, store.err
}

func (store *controlledTestStore) Revoke(_ context.Context, credentialID string, expiresAt time.Time) error {
	store.revokeCalls++
	store.revokedID = credentialID
	store.revokedUntil = expiresAt
	return store.err
}

type controlledTestUsers struct {
	currentUser user.Summary
	err         error
	reads       int
}

func (users *controlledTestUsers) GetByID(context.Context, int64) (user.Summary, error) {
	users.reads++
	return users.currentUser, users.err
}

func TestControlledAuthenticatorValidatesRevocationAndCurrentUser(t *testing.T) {
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(testSecret, "test-issuer", "test-audience", 2*time.Minute, "jwt-controlled")
	manager.now = func() time.Time { return now }
	issued, err := manager.Issue(context.Background(), testCredentials())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tests := []struct {
		name      string
		store     *controlledTestStore
		users     *controlledTestUsers
		wantError error
	}{
		{name: "valid", store: &controlledTestStore{}, users: validControlledUsers()},
		{name: "denylisted", store: &controlledTestStore{revoked: true}, users: validControlledUsers(), wantError: auth.ErrCredentialRevoked},
		{name: "blocked", store: &controlledTestStore{}, users: &controlledTestUsers{currentUser: user.Summary{ID: 7, Active: false, AuthVersion: 3}}, wantError: auth.ErrUserUnavailable},
		{name: "missing user", store: &controlledTestStore{}, users: &controlledTestUsers{err: user.ErrNotFound}, wantError: auth.ErrUserUnavailable},
		{name: "old auth version", store: &controlledTestStore{}, users: &controlledTestUsers{currentUser: user.Summary{ID: 7, Active: true, AuthVersion: 4}}, wantError: auth.ErrCredentialRevoked},
		{name: "revocation store error", store: &controlledTestStore{err: errors.New("store unavailable")}, users: validControlledUsers(), wantError: errControlledInfrastructure},
		{name: "user reader error", store: &controlledTestStore{}, users: &controlledTestUsers{err: errors.New("database unavailable")}, wantError: errControlledInfrastructure},
	}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			authenticator := NewControlledAuthenticator(manager, currentTest.store, currentTest.users)
			requestAuthentication, err := authenticator.Validate(context.Background(), issued.Value)
			if currentTest.wantError == nil {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if requestAuthentication.Identity.Name != "Usuario actual" || requestAuthentication.Identity.AuthVersion != 3 {
					t.Fatalf("Identity = %#v", requestAuthentication.Identity)
				}
				return
			}
			if errors.Is(currentTest.wantError, errControlledInfrastructure) {
				if err == nil || isCredentialError(err) {
					t.Fatalf("Validate() error = %v, want infrastructure error", err)
				}
				return
			}
			if !errors.Is(err, currentTest.wantError) {
				t.Fatalf("Validate() error = %v, want %v", err, currentTest.wantError)
			}
		})
	}
}

func TestControlledAuthenticatorValidatesCryptographyBeforeState(t *testing.T) {
	store := &controlledTestStore{err: errors.New("store unavailable")}
	users := validControlledUsers()
	manager := NewManager(testSecret, "test-issuer", "test-audience", time.Minute, "jwt-controlled")
	authenticator := NewControlledAuthenticator(manager, store, users)

	if _, err := authenticator.Validate(context.Background(), "tampered"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("Validate() error = %v, want ErrInvalidCredential", err)
	}
	if store.checks != 0 || users.reads != 0 {
		t.Fatalf("state checks after invalid JWT = store %d, users %d", store.checks, users.reads)
	}
}

func TestControlledAuthenticatorRevokesJTIUntilOriginalExpiration(t *testing.T) {
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(testSecret, "test-issuer", "test-audience", 2*time.Minute, "jwt-controlled")
	manager.now = func() time.Time { return now }
	issued, err := manager.Issue(context.Background(), testCredentials())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	store := &controlledTestStore{}
	authenticator := NewControlledAuthenticator(manager, store, validControlledUsers())

	if err := authenticator.Revoke(context.Background(), issued.Value); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if store.revokedID == "" || !store.revokedUntil.Equal(issued.ExpiresAt) {
		t.Fatalf("revocation = %q until %v, want jti until %v", store.revokedID, store.revokedUntil, issued.ExpiresAt)
	}
	manager.now = func() time.Time { return issued.ExpiresAt.Add(time.Second) }
	if err := authenticator.Revoke(context.Background(), issued.Value); err != nil {
		t.Fatalf("Revoke(expired) error = %v", err)
	}
	if err := authenticator.Revoke(context.Background(), "tampered"); err != nil {
		t.Fatalf("Revoke(tampered) error = %v", err)
	}
	if store.revokeCalls != 1 {
		t.Fatalf("store Revoke() calls = %d, want 1", store.revokeCalls)
	}
}

var errControlledInfrastructure = errors.New("infrastructure")

func validControlledUsers() *controlledTestUsers {
	return &controlledTestUsers{currentUser: user.Summary{
		ID: 7, Name: "Usuario actual", Email: "actual@poc.local", Role: user.RoleUser, Active: true, AuthVersion: 3,
	}}
}

func isCredentialError(err error) bool {
	return errors.Is(err, auth.ErrInvalidCredential) || errors.Is(err, auth.ErrCredentialExpired) || errors.Is(err, auth.ErrCredentialRevoked) || errors.Is(err, auth.ErrUserUnavailable)
}
