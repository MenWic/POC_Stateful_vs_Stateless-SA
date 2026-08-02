package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

func (handler *Handler) optionalAuthentication(next http.Handler) http.Handler {
	if handler.authentication == nil {
		return next
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		credentialValue, err := handler.authentication.Transport.Read(request)
		if errors.Is(err, auth.ErrMissingCredential) {
			next.ServeHTTP(writer, request)
			return
		}
		if err != nil {
			if isUnusableCredentialError(err) {
				handler.authentication.Transport.Clear(writer)
			} else {
				handler.logger.Printf("no fue posible leer autenticación opcional: %v", err)
			}
			next.ServeHTTP(writer, request)
			return
		}

		requestAuthentication, err := handler.validateCredential(request.Context(), credentialValue)
		if err != nil {
			if isUnusableCredentialError(err) {
				handler.authentication.Transport.Clear(writer)
			} else {
				handler.logger.Printf("no fue posible validar autenticación opcional: %v", err)
			}
			next.ServeHTTP(writer, request)
			return
		}
		requestAuthentication, err = handler.withCSRFToken(writer, request, requestAuthentication)
		if err != nil {
			handler.logger.Printf("no fue posible preparar CSRF para autenticación opcional: %v", err)
			next.ServeHTTP(writer, request)
			return
		}

		ctx := auth.WithRequestAuthentication(request.Context(), requestAuthentication)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (handler *Handler) requireAuthentication(apiRequest bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			credentialValue, err := handler.authentication.Transport.Read(request)
			if err != nil {
				if errors.Is(err, auth.ErrMissingCredential) {
					handler.handleUnauthenticated(writer, request, apiRequest, err)
					return
				}
				if isUnusableCredentialError(err) {
					handler.authentication.Transport.Clear(writer)
					handler.handleUnauthenticated(writer, request, apiRequest, err)
					return
				}
				handler.logger.Printf("no fue posible leer autenticación: %v", err)
				http.Error(writer, "No fue posible validar la credencial", http.StatusInternalServerError)
				return
			}

			requestAuthentication, err := handler.validateCredential(request.Context(), credentialValue)
			if err != nil {
				if isUnusableCredentialError(err) {
					handler.authentication.Transport.Clear(writer)
					handler.handleUnauthenticated(writer, request, apiRequest, err)
					return
				}
				handler.logger.Printf("no fue posible validar autenticación: %v", err)
				http.Error(writer, "No fue posible validar la credencial", http.StatusInternalServerError)
				return
			}
			requestAuthentication, err = handler.withCSRFToken(writer, request, requestAuthentication)
			if err != nil {
				handler.logger.Printf("no fue posible preparar CSRF: %v", err)
				http.Error(writer, "No fue posible preparar la solicitud autenticada", http.StatusInternalServerError)
				return
			}

			ctx := auth.WithRequestAuthentication(request.Context(), requestAuthentication)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func (handler *Handler) validateCredential(ctx context.Context, credentialValue string) (auth.RequestAuthentication, error) {
	startedAt := time.Now()
	requestAuthentication, err := handler.authentication.Validator.Validate(ctx, credentialValue)
	duration := time.Since(startedAt)
	if err != nil {
		return auth.RequestAuthentication{}, err
	}

	requestAuthentication.Validation = handler.authentication.Validation
	requestAuthentication.Validation.Duration = duration
	return requestAuthentication, nil
}

func (handler *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestAuthentication, exists := auth.FromContext(request.Context())
		if !exists {
			http.Error(writer, "Autenticación requerida", http.StatusUnauthorized)
			return
		}
		if requestAuthentication.Identity.Role != user.RoleAdmin {
			http.Error(writer, "Acceso prohibido", http.StatusForbidden)
			return
		}

		next.ServeHTTP(writer, request)
	})
}

func (handler *Handler) handleUnauthenticated(writer http.ResponseWriter, request *http.Request, apiRequest bool, err error) {
	if apiRequest {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		message := apiAuthenticationErrorMessage(err)
		if _, writeErr := writer.Write([]byte("{\"error\":\"" + message + "\"}\n")); writeErr != nil {
			handler.logger.Printf("no fue posible responder autenticación requerida: %v", writeErr)
		}
		return
	}

	reason := authenticationReason(err)
	http.Redirect(writer, request, "/login?reason="+url.QueryEscape(reason), http.StatusSeeOther)
}

func apiAuthenticationErrorMessage(err error) string {
	switch {
	case errors.Is(err, auth.ErrIdleExpired):
		return "sesión expirada por inactividad"
	case errors.Is(err, auth.ErrAbsoluteExpired):
		return "sesión con duración máxima alcanzada"
	case errors.Is(err, auth.ErrCredentialExpired):
		return "token expirado"
	case errors.Is(err, auth.ErrCredentialRevoked):
		return "credencial revocada"
	case errors.Is(err, auth.ErrUserUnavailable):
		return "cuenta bloqueada o no disponible"
	case errors.Is(err, auth.ErrInvalidCredential):
		return "credencial inválida"
	default:
		return "autenticación requerida"
	}
}

func authenticationReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrIdleExpired):
		return "idle"
	case errors.Is(err, auth.ErrAbsoluteExpired):
		return "absolute"
	case errors.Is(err, auth.ErrCredentialRevoked):
		return "revoked"
	case errors.Is(err, auth.ErrUserUnavailable):
		return "blocked"
	case errors.Is(err, auth.ErrInvalidCredential):
		return "invalid"
	case errors.Is(err, auth.ErrCredentialExpired):
		return "expired"
	default:
		return "required"
	}
}

func isUnusableCredentialError(err error) bool {
	return errors.Is(err, auth.ErrInvalidCredential) ||
		errors.Is(err, auth.ErrCredentialExpired) ||
		errors.Is(err, auth.ErrIdleExpired) ||
		errors.Is(err, auth.ErrAbsoluteExpired) ||
		errors.Is(err, auth.ErrCredentialRevoked) ||
		errors.Is(err, auth.ErrUserUnavailable)
}

func (handler *Handler) withCSRFToken(writer http.ResponseWriter, request *http.Request, requestAuthentication auth.RequestAuthentication) (auth.RequestAuthentication, error) {
	if handler.authentication.CSRFTransport == nil {
		return requestAuthentication, nil
	}

	csrfToken, err := handler.authentication.CSRFTransport.Read(request)
	if err != nil {
		csrfToken, err = handler.authentication.CSRFTransport.Issue(writer, requestAuthentication.Identity.ExpiresAt)
		if err != nil {
			return auth.RequestAuthentication{}, err
		}
	}
	requestAuthentication.CSRFToken = csrfToken
	return requestAuthentication, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}
