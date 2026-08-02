package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const csrfTokenBytes = 32

func GenerateCSRFToken() (string, error) {
	randomBytes := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generar token CSRF: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func CSRFTokenMatches(expected, provided string) bool {
	if expected == "" || provided == "" || len(expected) != len(provided) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}
