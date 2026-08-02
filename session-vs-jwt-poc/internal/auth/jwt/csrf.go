package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/security"
)

const csrfCookieName = "jwt_csrf"

type CSRFTokenTransport struct {
	secret []byte
	secure bool
}

func NewCSRFTokenTransport(secret []byte, secure bool) *CSRFTokenTransport {
	return &CSRFTokenTransport{secret: append([]byte(nil), secret...), secure: secure}
}

func (transport *CSRFTokenTransport) Read(request *http.Request) (string, error) {
	cookie, err := request.Cookie(csrfCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", auth.ErrMissingCredential
	}
	if err != nil || !transport.valid(cookie.Value) {
		return "", auth.ErrInvalidCredential
	}

	return cookie.Value, nil
}

func (transport *CSRFTokenTransport) Issue(writer http.ResponseWriter, expiresAt time.Time) (string, error) {
	randomToken, err := security.GenerateCSRFToken()
	if err != nil {
		return "", err
	}
	signature, err := transport.signature(randomToken)
	if err != nil {
		return "", err
	}
	signedToken := randomToken + "." + signature
	http.SetCookie(writer, transport.cookie(signedToken, expiresAt, cookieMaxAge(expiresAt)))
	return signedToken, nil
}

func (transport *CSRFTokenTransport) Clear(writer http.ResponseWriter) {
	http.SetCookie(writer, transport.cookie("", time.Unix(1, 0).UTC(), -1))
}

func (transport *CSRFTokenTransport) valid(signedToken string) bool {
	randomToken, providedSignature, found := strings.Cut(signedToken, ".")
	if !found || randomToken == "" || providedSignature == "" {
		return false
	}
	randomBytes, err := base64.RawURLEncoding.DecodeString(randomToken)
	if err != nil || len(randomBytes) != 32 {
		return false
	}
	expectedEncodedSignature, err := transport.signature(randomToken)
	if err != nil {
		return false
	}
	expectedSignature, err := base64.RawURLEncoding.DecodeString(expectedEncodedSignature)
	if err != nil {
		return false
	}
	providedBytes, err := base64.RawURLEncoding.DecodeString(providedSignature)
	if err != nil {
		return false
	}

	return hmac.Equal(expectedSignature, providedBytes)
}

func (transport *CSRFTokenTransport) signature(randomToken string) (string, error) {
	mac := hmac.New(sha256.New, transport.secret)
	if _, err := mac.Write([]byte("jwt-csrf:" + randomToken)); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (transport *CSRFTokenTransport) cookie(value string, expiresAt time.Time, maxAge int) *http.Cookie {
	// El formulario recibe el valor desde el servidor y no necesita exponer la cookie a JavaScript
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   transport.secure,
		SameSite: http.SameSiteLaxMode,
	}
}
