package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

var testSecret = []byte("a-local-test-secret-with-at-least-32-bytes")

func TestManagerIssuesAndValidatesStatelessIdentityAcrossInstances(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	issuer := NewManager(testSecret, "test-issuer", "test-audience", 2*time.Minute, "jwt-a")
	issuer.now = func() time.Time { return now }
	validator := NewManager(testSecret, "test-issuer", "test-audience", 2*time.Minute, "jwt-b")
	validator.now = func() time.Time { return now.Add(time.Second) }

	issued, err := issuer.Issue(context.Background(), testCredentials())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	authentication, err := validator.Validate(context.Background(), issued.Value)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	identity := authentication.Identity
	if identity.UserID != 7 || identity.Name != "Usuario" || identity.Email != "user@poc.local" || identity.Role != user.RoleUser {
		t.Fatalf("Identity = %#v", identity)
	}
	if identity.AuthenticationMethod != "jwt" || identity.InstanceID != "jwt-b" || identity.CredentialID == "" || identity.AuthVersion != 3 {
		t.Fatalf("Identity technical fields = %#v", identity)
	}
	if !identity.AuthenticatedAt.Equal(now) || !identity.ExpiresAt.Equal(now.Add(2*time.Minute)) || !identity.IdleExpiresAt.IsZero() {
		t.Fatalf("Identity expiration fields = %#v", identity)
	}
	if authentication.CSRFToken != "" {
		t.Fatal("JWT included a CSRF token in its identity claims")
	}

	payload := strings.Split(issued.Value, ".")[1]
	decodedPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(strings.ToLower(string(decodedPayload)), "password") || strings.Contains(string(decodedPayload), "User123!") {
		t.Fatalf("JWT payload contains password data: %s", decodedPayload)
	}
}

func TestManagerRejectsExpiredToken(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	manager := NewManager(testSecret, "test-issuer", "test-audience", time.Minute, "jwt-a")
	manager.now = func() time.Time { return now }
	issued, err := manager.Issue(context.Background(), testCredentials())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	manager.now = func() time.Time { return now.Add(time.Minute) }

	if _, err := manager.Validate(context.Background(), issued.Value); !errors.Is(err, auth.ErrCredentialExpired) {
		t.Fatalf("Validate() error = %v, want ErrCredentialExpired", err)
	}
}

func TestManagerRejectsInvalidSignatureIssuerAudienceAndTampering(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	issuer := NewManager(testSecret, "test-issuer", "test-audience", time.Minute, "jwt-a")
	issuer.now = func() time.Time { return now }
	issued, err := issuer.Issue(context.Background(), testCredentials())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tests := []struct {
		name      string
		validator *Manager
		token     string
	}{
		{name: "different secret", validator: NewManager([]byte("another-local-test-secret-with-32-bytes"), "test-issuer", "test-audience", time.Minute, "jwt-b"), token: issued.Value},
		{name: "incorrect issuer", validator: NewManager(testSecret, "other-issuer", "test-audience", time.Minute, "jwt-b"), token: issued.Value},
		{name: "incorrect audience", validator: NewManager(testSecret, "test-issuer", "other-audience", time.Minute, "jwt-b"), token: issued.Value},
		{name: "tampered payload", validator: NewManager(testSecret, "test-issuer", "test-audience", time.Minute, "jwt-b"), token: tamperPayload(issued.Value)},
	}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			currentTest.validator.now = func() time.Time { return now.Add(time.Second) }
			if _, err := currentTest.validator.Validate(context.Background(), currentTest.token); !errors.Is(err, auth.ErrInvalidCredential) {
				t.Fatalf("Validate() error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestManagerRejectsUnexpectedAlgorithmAndMissingOwnClaims(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	manager := NewManager(testSecret, "test-issuer", "test-audience", time.Minute, "jwt-a")
	manager.now = func() time.Time { return now }
	claims := validTestClaims(now)

	noneToken, err := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, claims).SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	if _, err := manager.Validate(context.Background(), noneToken); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("Validate(none) error = %v, want ErrInvalidCredential", err)
	}

	invalidClaims := validTestClaims(now)
	invalidClaims.ID = ""
	invalidToken, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, invalidClaims).SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign incomplete token: %v", err)
	}
	if _, err := manager.Validate(context.Background(), invalidToken); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("Validate(incomplete) error = %v, want ErrInvalidCredential", err)
	}
}

func testCredentials() user.ValidatedCredentials {
	return user.ValidatedCredentials{
		UserID: 7, Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, AuthVersion: 3,
	}
}

func validTestClaims(now time.Time) Claims {
	return Claims{
		Name: "Usuario", Email: "user@poc.local", Role: user.RoleUser, AuthVersion: 3,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer: "test-issuer", Subject: "7", Audience: jwtlib.ClaimStrings{"test-audience"},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(time.Minute)), IssuedAt: jwtlib.NewNumericDate(now), ID: "test-jti",
		},
	}
}

func tamperPayload(token string) string {
	parts := strings.Split(token, ".")
	if parts[1][0] == 'a' {
		parts[1] = "b" + parts[1][1:]
	} else {
		parts[1] = "a" + parts[1][1:]
	}
	return strings.Join(parts, ".")
}
