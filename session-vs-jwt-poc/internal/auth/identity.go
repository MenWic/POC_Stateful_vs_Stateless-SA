package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"session-vs-jwt-poc/internal/user"
)

var (
	ErrMissingCredential = errors.New("credencial ausente")
	ErrInvalidCredential = errors.New("credencial inválida")
	ErrCredentialExpired = errors.New("credencial expirada")
	ErrIdleExpired       = errors.New("sesión expirada por inactividad")
	ErrAbsoluteExpired   = errors.New("sesión expirada absolutamente")
	ErrCredentialRevoked = errors.New("credencial revocada")
	ErrUserUnavailable   = errors.New("usuario no disponible")
)

type Identity struct {
	UserID               int64
	Name                 string
	Email                string
	Role                 user.Role
	AuthVersion          int64
	AuthenticatedAt      time.Time
	ExpiresAt            time.Time
	IdleExpiresAt        time.Time
	AuthenticationMethod string
	CredentialID         string
	InstanceID           string
}

type IssuedCredential struct {
	Value     string
	ExpiresAt time.Time
}

type RequestAuthentication struct {
	Identity   Identity
	CSRFToken  string
	Validation ValidationMetadata
}

type ValidationMetadata struct {
	Duration           time.Duration
	ServerStateChecked bool
	CurrentUserChecked bool
	StoreName          string
	Description        string
}

type CredentialIssuer interface {
	Issue(ctx context.Context, credentials user.ValidatedCredentials) (IssuedCredential, error)
}

type CredentialValidator interface {
	Validate(ctx context.Context, credentialValue string) (RequestAuthentication, error)
}

type CredentialRevoker interface {
	Revoke(ctx context.Context, credentialValue string) error
	RevokeUser(ctx context.Context, userID int64) error
}

type CredentialTransport interface {
	Read(request *http.Request) (string, error)
	Write(writer http.ResponseWriter, credential IssuedCredential)
	Clear(writer http.ResponseWriter)
}

type CSRFTokenTransport interface {
	Read(request *http.Request) (string, error)
	Issue(writer http.ResponseWriter, expiresAt time.Time) (string, error)
	Clear(writer http.ResponseWriter)
}

type requestAuthenticationKey struct{}

func WithRequestAuthentication(ctx context.Context, authentication RequestAuthentication) context.Context {
	return context.WithValue(ctx, requestAuthenticationKey{}, authentication)
}

func FromContext(ctx context.Context) (RequestAuthentication, bool) {
	authentication, exists := ctx.Value(requestAuthenticationKey{}).(RequestAuthentication)
	return authentication, exists
}
