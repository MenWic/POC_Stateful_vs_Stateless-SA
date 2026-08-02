package web

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth"
)

type middlewareTransport struct {
	readErr error
	cleared bool
}

func (transport *middlewareTransport) Read(*http.Request) (string, error) {
	if transport.readErr != nil {
		return "", transport.readErr
	}
	return "credential", nil
}

func (*middlewareTransport) Write(http.ResponseWriter, auth.IssuedCredential) {}

func (transport *middlewareTransport) Clear(http.ResponseWriter) {
	transport.cleared = true
}

type middlewareValidator struct {
	err error
}

func (validator middlewareValidator) Validate(context.Context, string) (auth.RequestAuthentication, error) {
	if validator.err != nil {
		return auth.RequestAuthentication{}, validator.err
	}
	return auth.RequestAuthentication{Identity: auth.Identity{ExpiresAt: time.Now().Add(time.Minute)}}, nil
}

func TestRequireAuthenticationClearsOnlyUnusableCredentials(t *testing.T) {
	tests := []struct {
		name       string
		validation error
		wantClear  bool
		wantStatus int
		wantError  string
	}{
		{name: "invalid", validation: auth.ErrInvalidCredential, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "credencial inválida"},
		{name: "token expired", validation: auth.ErrCredentialExpired, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "token expirado"},
		{name: "idle expired", validation: auth.ErrIdleExpired, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "sesión expirada por inactividad"},
		{name: "absolute expired", validation: auth.ErrAbsoluteExpired, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "sesión con duración máxima alcanzada"},
		{name: "revoked", validation: auth.ErrCredentialRevoked, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "credencial revocada"},
		{name: "user unavailable", validation: auth.ErrUserUnavailable, wantClear: true, wantStatus: http.StatusUnauthorized, wantError: "cuenta bloqueada o no disponible"},
		{name: "infrastructure", validation: errors.New("Redis no disponible"), wantClear: false, wantStatus: http.StatusInternalServerError},
	}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			transport := &middlewareTransport{}
			handler := middlewareTestHandler(transport, currentTest.validation)
			protected := handler.requireAuthentication(true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("protected handler was called")
			}))
			response := httptest.NewRecorder()

			protected.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/me", nil))

			if response.Code != currentTest.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, currentTest.wantStatus)
			}
			if transport.cleared != currentTest.wantClear {
				t.Fatalf("cookie cleared = %t, want %t", transport.cleared, currentTest.wantClear)
			}
			if currentTest.wantError != "" && !strings.Contains(response.Body.String(), currentTest.wantError) {
				t.Fatalf("response body = %q, want error %q", response.Body.String(), currentTest.wantError)
			}
		})
	}
}

func TestRequireAuthenticationDoesNotClearMissingCredential(t *testing.T) {
	transport := &middlewareTransport{readErr: auth.ErrMissingCredential}
	handler := middlewareTestHandler(transport, nil)
	response := httptest.NewRecorder()

	handler.requireAuthentication(true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/me", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if transport.cleared {
		t.Fatal("missing credential cleared cookie")
	}
}

func TestOptionalAuthenticationClearsOnlyUnusableCredentials(t *testing.T) {
	tests := []struct {
		name       string
		validation error
		wantClear  bool
	}{
		{name: "invalid", validation: auth.ErrInvalidCredential, wantClear: true},
		{name: "infrastructure", validation: errors.New("Redis no disponible"), wantClear: false},
	}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			transport := &middlewareTransport{}
			handler := middlewareTestHandler(transport, currentTest.validation)
			response := httptest.NewRecorder()
			publicCalled := false

			handler.optionalAuthentication(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				publicCalled = true
				writer.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

			if !publicCalled || response.Code != http.StatusNoContent {
				t.Fatalf("public response called = %t, status = %d", publicCalled, response.Code)
			}
			if transport.cleared != currentTest.wantClear {
				t.Fatalf("cookie cleared = %t, want %t", transport.cleared, currentTest.wantClear)
			}
		})
	}
}

func TestValidateCredentialAddsConfiguredMetadata(t *testing.T) {
	handler := middlewareTestHandler(&middlewareTransport{}, nil)
	handler.authentication.Validation = auth.ValidationMetadata{
		StoreName:          "redis",
		ServerStateChecked: true,
		CurrentUserChecked: true,
		Description:        "firma + claims + denylist Redis + usuario actual",
	}

	requestAuthentication, err := handler.validateCredential(context.Background(), "credential")
	if err != nil {
		t.Fatalf("validateCredential() error = %v", err)
	}
	if requestAuthentication.Validation.StoreName != "redis" ||
		!requestAuthentication.Validation.ServerStateChecked ||
		!requestAuthentication.Validation.CurrentUserChecked ||
		requestAuthentication.Validation.Description == "" {
		t.Fatalf("validation metadata = %+v", requestAuthentication.Validation)
	}
	if requestAuthentication.Validation.Duration < 0 {
		t.Fatalf("validation duration = %s, want non-negative", requestAuthentication.Validation.Duration)
	}
}

func middlewareTestHandler(transport *middlewareTransport, validationError error) *Handler {
	return &Handler{
		logger: log.New(io.Discard, "", 0),
		authentication: &Authentication{
			Validator: middlewareValidator{err: validationError},
			Transport: transport,
		},
	}
}
