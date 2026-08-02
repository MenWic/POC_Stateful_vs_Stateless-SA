package session

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"session-vs-jwt-poc/internal/auth"
)

const cookieName = "session_id"

type CookieTransport struct {
	secure bool
}

func NewCookieTransport(secure bool) *CookieTransport {
	return &CookieTransport{secure: secure}
}

func (transport *CookieTransport) Read(request *http.Request) (string, error) {
	cookie, err := request.Cookie(cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", auth.ErrMissingCredential
	}
	if err != nil {
		return "", auth.ErrInvalidCredential
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(decodedID) != sessionIDBytes {
		return "", auth.ErrInvalidCredential
	}

	return cookie.Value, nil
}

func (transport *CookieTransport) Write(writer http.ResponseWriter, credential auth.IssuedCredential) {
	maxAge := int(time.Until(credential.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(writer, transport.cookie(credential.Value, credential.ExpiresAt, maxAge))
}

func (transport *CookieTransport) Clear(writer http.ResponseWriter) {
	http.SetCookie(writer, transport.cookie("", time.Unix(1, 0).UTC(), -1))
}

func (transport *CookieTransport) cookie(value string, expiresAt time.Time, maxAge int) *http.Cookie {
	// Secure se desactiva únicamente para HTTP local y debe habilitarse cuando exista HTTPS
	return &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   transport.secure,
		SameSite: http.SameSiteLaxMode,
	}
}
