package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/security"
)

func TestCSRFTokenTransportIssuesAndValidatesSignedDoubleSubmitCookie(t *testing.T) {
	transport := NewCSRFTokenTransport(testSecret, true)
	response := httptest.NewRecorder()
	expiresAt := time.Now().Add(time.Minute)
	issuedToken, err := transport.Issue(response, expiresAt)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != csrfCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("CSRF cookie = %#v", cookie)
	}

	request := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	request.AddCookie(cookie)
	readToken, err := transport.Read(request)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !security.CSRFTokenMatches(issuedToken, readToken) {
		t.Fatal("signed CSRF cookie did not match the form token")
	}

	tamperedRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
	tamperedRequest.AddCookie(&http.Cookie{Name: csrfCookieName, Value: cookie.Value + "changed"})
	if _, err := transport.Read(tamperedRequest); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("Read(tampered) error = %v, want ErrInvalidCredential", err)
	}
}

func TestCookieTransportUsesAccessTokenCookie(t *testing.T) {
	transport := NewCookieTransport(true)
	response := httptest.NewRecorder()
	transport.Write(response, auth.IssuedCredential{Value: "header.payload.signature", ExpiresAt: time.Now().Add(time.Minute)})
	cookie := response.Result().Cookies()[0]
	if cookie.Name != accessTokenCookieName || cookie.Value != "header.payload.signature" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("access token cookie = %#v", cookie)
	}
}
