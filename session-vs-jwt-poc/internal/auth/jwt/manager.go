package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

const jwtIDBytes = 32

type Claims struct {
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Role        user.Role `json:"role"`
	AuthVersion int64     `json:"auth_version"`
	jwtlib.RegisteredClaims
}

func (claims Claims) Validate() error {
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID < 1 {
		return fmt.Errorf("sub inválido")
	}
	if claims.ID == "" || claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return fmt.Errorf("claims registrados incompletos")
	}
	if claims.Name == "" || claims.Email == "" || claims.AuthVersion < 1 {
		return fmt.Errorf("claims de identidad incompletos")
	}
	if claims.Role != user.RoleAdmin && claims.Role != user.RoleUser {
		return fmt.Errorf("role inválido")
	}
	if !claims.IssuedAt.Time.Before(claims.ExpiresAt.Time) {
		return fmt.Errorf("intervalo temporal inválido")
	}

	return nil
}

type Manager struct {
	secret     []byte
	issuer     string
	audience   string
	ttl        time.Duration
	instanceID string
	now        func() time.Time
}

func NewManager(secret []byte, issuer, audience string, ttl time.Duration, instanceID string) *Manager {
	secretCopy := append([]byte(nil), secret...)
	return &Manager{
		secret:     secretCopy,
		issuer:     issuer,
		audience:   audience,
		ttl:        ttl,
		instanceID: instanceID,
		now:        time.Now,
	}
}

func (manager *Manager) Issue(_ context.Context, credentials user.ValidatedCredentials) (auth.IssuedCredential, error) {
	credentialID, err := generateJWTID()
	if err != nil {
		return auth.IssuedCredential{}, err
	}

	now := manager.now().UTC()
	expiresAt := now.Add(manager.ttl)
	claims := Claims{
		Name:        credentials.Name,
		Email:       credentials.Email,
		Role:        credentials.Role,
		AuthVersion: credentials.AuthVersion,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    manager.issuer,
			Subject:   strconv.FormatInt(credentials.UserID, 10),
			Audience:  jwtlib.ClaimStrings{manager.audience},
			ExpiresAt: jwtlib.NewNumericDate(expiresAt),
			IssuedAt:  jwtlib.NewNumericDate(now),
			ID:        credentialID,
		},
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(manager.secret)
	if err != nil {
		return auth.IssuedCredential{}, fmt.Errorf("firmar JWT: %w", err)
	}

	return auth.IssuedCredential{Value: signedToken, ExpiresAt: expiresAt}, nil
}

func (manager *Manager) Validate(_ context.Context, credentialValue string) (auth.RequestAuthentication, error) {
	claims := &Claims{}
	token, err := jwtlib.ParseWithClaims(
		credentialValue,
		claims,
		func(token *jwtlib.Token) (any, error) {
			if token.Method != jwtlib.SigningMethodHS256 {
				return nil, auth.ErrInvalidCredential
			}
			return manager.secret, nil
		},
		jwtlib.WithValidMethods([]string{jwtlib.SigningMethodHS256.Alg()}),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithIssuedAt(),
		jwtlib.WithIssuer(manager.issuer),
		jwtlib.WithAudience(manager.audience),
		jwtlib.WithTimeFunc(manager.now),
		jwtlib.WithStrictDecoding(),
	)
	if err != nil {
		if errors.Is(err, jwtlib.ErrTokenExpired) {
			return auth.RequestAuthentication{}, auth.ErrCredentialExpired
		}
		return auth.RequestAuthentication{}, auth.ErrInvalidCredential
	}
	if !token.Valid {
		return auth.RequestAuthentication{}, auth.ErrInvalidCredential
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID < 1 {
		return auth.RequestAuthentication{}, auth.ErrInvalidCredential
	}

	return auth.RequestAuthentication{Identity: auth.Identity{
		UserID:               userID,
		Name:                 claims.Name,
		Email:                claims.Email,
		Role:                 claims.Role,
		AuthVersion:          claims.AuthVersion,
		AuthenticatedAt:      claims.IssuedAt.Time.UTC(),
		ExpiresAt:            claims.ExpiresAt.Time.UTC(),
		AuthenticationMethod: "jwt",
		CredentialID:         claims.ID,
		InstanceID:           manager.instanceID,
	}}, nil
}

func generateJWTID() (string, error) {
	randomBytes := make([]byte, jwtIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generar jti: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
