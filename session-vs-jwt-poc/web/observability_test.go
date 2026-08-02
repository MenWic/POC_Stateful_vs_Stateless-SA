package web

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

func TestAPIMeIncludesSafeValidationMetadata(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		securityMode       string
		store              string
		serverStateChecked bool
		userStateChecked   bool
		wantMode           string
	}{
		{name: "session memory", method: "session", securityMode: "session", store: "memory", serverStateChecked: true, userStateChecked: true, wantMode: "stateful"},
		{name: "session redis", method: "session", securityMode: "session", store: "redis", serverStateChecked: true, userStateChecked: true, wantMode: "stateful"},
		{name: "JWT pure", method: "jwt", securityMode: "pure", store: "none", wantMode: "pure"},
		{name: "JWT controlled memory", method: "jwt", securityMode: "controlled", store: "memory", serverStateChecked: true, userStateChecked: true, wantMode: "controlled"},
		{name: "JWT controlled Redis", method: "jwt", securityMode: "controlled", store: "redis", serverStateChecked: true, userStateChecked: true, wantMode: "controlled"},
	}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			handler := &Handler{
				logger: log.New(io.Discard, "", 0),
				authentication: &Authentication{
					SecurityMode: currentTest.securityMode,
				},
			}
			fullCredentialID := "credential-identifier-must-remain-private"
			requestAuthentication := auth.RequestAuthentication{
				Identity: auth.Identity{
					UserID:               2,
					Name:                 "Usuario Demo",
					Email:                "user@poc.local",
					Role:                 user.RoleUser,
					AuthenticatedAt:      time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC),
					ExpiresAt:            time.Date(2026, time.August, 11, 13, 0, 0, 0, time.UTC),
					AuthenticationMethod: currentTest.method,
					CredentialID:         fullCredentialID,
					InstanceID:           "test-instance",
				},
				Validation: auth.ValidationMetadata{
					Duration:           640 * time.Microsecond,
					StoreName:          currentTest.store,
					ServerStateChecked: currentTest.serverStateChecked,
					CurrentUserChecked: currentTest.userStateChecked,
					Description:        "descripción segura",
				},
			}
			request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			request = request.WithContext(auth.WithRequestAuthentication(request.Context(), requestAuthentication))
			response := httptest.NewRecorder()

			handler.apiMe(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			var body meResponse
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decode /api/me: %v", err)
			}
			if body.Mode != currentTest.wantMode || body.Store != currentTest.store ||
				body.ServerStateChecked != currentTest.serverStateChecked ||
				body.UserStateChecked != currentTest.userStateChecked ||
				body.ValidationDurationUS != 640 {
				t.Fatalf("/api/me validation metadata = %+v", body)
			}
			if body.CredentialID == fullCredentialID || body.CredentialID != "credential…" {
				t.Fatalf("credential_id = %q, want truncated value", body.CredentialID)
			}
		})
	}
}

func TestFormatValidationDurationUsesPedagogicPrecision(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     string
	}{
		{duration: 400 * time.Nanosecond, want: "<1 µs"},
		{duration: 84 * time.Microsecond, want: "84 µs"},
		{duration: 1264 * time.Microsecond, want: "1.26 ms"},
	}
	for _, currentTest := range tests {
		if got := formatValidationDuration(currentTest.duration); got != currentTest.want {
			t.Errorf("formatValidationDuration(%s) = %q, want %q", currentTest.duration, got, currentTest.want)
		}
	}
}
