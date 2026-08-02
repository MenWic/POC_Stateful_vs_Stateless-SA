package jwt

import (
	"errors"
	"net/http"
	"time"

	"session-vs-jwt-poc/internal/auth"
)

const accessTokenCookieName = "access_token"

type CookieTransport struct {
	secure bool
}

func NewCookieTransport(secure bool) *CookieTransport {
	return &CookieTransport{secure: secure}
}

func (transport *CookieTransport) Read(request *http.Request) (string, error) {
	cookie, err := request.Cookie(accessTokenCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", auth.ErrMissingCredential
	}
	if err != nil || cookie.Value == "" {
		return "", auth.ErrInvalidCredential
	}

	return cookie.Value, nil
}

func (transport *CookieTransport) Write(writer http.ResponseWriter, credential auth.IssuedCredential) {
	http.SetCookie(writer, transport.cookie(credential.Value, credential.ExpiresAt, cookieMaxAge(credential.ExpiresAt)))
}

func (transport *CookieTransport) Clear(writer http.ResponseWriter) {
	http.SetCookie(writer, transport.cookie("", time.Unix(1, 0).UTC(), -1))
}

func (transport *CookieTransport) cookie(value string, expiresAt time.Time, maxAge int) *http.Cookie {
	// Secure se desactiva únicamente para HTTP local y debe habilitarse cuando exista HTTPS
	return &http.Cookie{
		Name:     accessTokenCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   transport.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func cookieMaxAge(expiresAt time.Time) int {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		return 1
	}
	return maxAge
}
