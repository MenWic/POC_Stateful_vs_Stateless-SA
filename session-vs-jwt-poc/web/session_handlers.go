package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/security"
	"session-vs-jwt-poc/internal/user"
)

type meResponse struct {
	UserID               int64  `json:"user_id"`
	Name                 string `json:"name"`
	Email                string `json:"email"`
	Role                 string `json:"role"`
	AuthenticationMethod string `json:"authentication_method"`
	InstanceID           string `json:"instance"`
	AuthenticatedAt      string `json:"authenticated_at"`
	IdleExpiresAt        string `json:"idle_expires_at"`
	AbsoluteExpiresAt    string `json:"absolute_expires_at"`
	CredentialID         string `json:"credential_id"`
	Mode                 string `json:"mode"`
	Store                string `json:"store"`
	ServerStateChecked   bool   `json:"server_state_checked"`
	UserStateChecked     bool   `json:"user_state_checked"`
	ValidationDurationUS int64  `json:"validation_duration_us"`
}

func (handler *Handler) dashboard(writer http.ResponseWriter, request *http.Request) {
	successMessage := ""
	if request.URL.Query().Get("message") == "login" {
		successMessage = "Inicio de sesión correcto"
	}
	handler.render(writer, http.StatusOK, "dashboard", viewData{
		Title:          "Dashboard",
		CurrentPage:    "dashboard",
		SuccessMessage: successMessage,
	}, request)
}

func (handler *Handler) passwordForm(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusOK, "password", viewData{
		Title:       "Cambio de contraseña",
		CurrentPage: "password",
	}, request)
}

func (handler *Handler) changePassword(writer http.ResponseWriter, request *http.Request) {
	if !handler.parseProtectedForm(writer, request) {
		return
	}

	requestAuthentication, _ := auth.FromContext(request.Context())
	_, err := handler.userService.ChangePassword(
		request.Context(),
		requestAuthentication.Identity.UserID,
		request.PostFormValue("current_password"),
		request.PostFormValue("new_password"),
		request.PostFormValue("confirmation"),
	)
	if err != nil {
		if message, expected := passwordErrorMessage(err); expected {
			handler.render(writer, http.StatusBadRequest, "password", viewData{
				Title:        "Cambio de contraseña",
				CurrentPage:  "password",
				ErrorMessage: message,
			}, request)
			return
		}
		handler.logger.Printf("no fue posible cambiar la contraseña: %v", err)
		http.Error(writer, "No fue posible cambiar la contraseña", http.StatusInternalServerError)
		return
	}

	if handler.authentication.Revoker != nil {
		if err := handler.authentication.Revoker.RevokeUser(request.Context(), requestAuthentication.Identity.UserID); err != nil {
			handler.logger.Printf("no fue posible revocar sesiones después de cambiar contraseña: %v", err)
			http.Error(writer, "La contraseña cambió, pero no fue posible finalizar las sesiones", http.StatusInternalServerError)
			return
		}
	}
	handler.authentication.Transport.Clear(writer)
	if handler.authentication.CSRFTransport != nil {
		handler.authentication.CSRFTransport.Clear(writer)
	}
	http.Redirect(writer, request, "/login?reason=password", http.StatusSeeOther)
}

func (handler *Handler) logout(writer http.ResponseWriter, request *http.Request) {
	if !handler.parseProtectedForm(writer, request) {
		return
	}

	if handler.authentication.Revoker != nil {
		credentialValue, err := handler.authentication.Transport.Read(request)
		if err != nil {
			handler.logger.Printf("no fue posible releer la credencial durante logout: %v", err)
			http.Error(writer, "No fue posible cerrar la sesión", http.StatusInternalServerError)
			return
		}
		if err := handler.authentication.Revoker.Revoke(request.Context(), credentialValue); err != nil {
			handler.logger.Printf("no fue posible cerrar la sesión: %v", err)
			http.Error(writer, "No fue posible cerrar la sesión", http.StatusInternalServerError)
			return
		}
	}
	handler.authentication.Transport.Clear(writer)
	if handler.authentication.CSRFTransport != nil {
		handler.authentication.CSRFTransport.Clear(writer)
	}
	http.Redirect(writer, request, "/login?reason=logout", http.StatusSeeOther)
}

func (handler *Handler) apiMe(writer http.ResponseWriter, request *http.Request) {
	requestAuthentication, _ := auth.FromContext(request.Context())
	identity := requestAuthentication.Identity
	validation := requestAuthentication.Validation
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(writer).Encode(meResponse{
		UserID:               identity.UserID,
		Name:                 identity.Name,
		Email:                identity.Email,
		Role:                 string(identity.Role),
		AuthenticationMethod: identity.AuthenticationMethod,
		InstanceID:           identity.InstanceID,
		AuthenticatedAt:      identity.AuthenticatedAt.UTC().Format(timeLayout),
		IdleExpiresAt:        formatOptionalAPITime(identity.IdleExpiresAt),
		AbsoluteExpiresAt:    identity.ExpiresAt.UTC().Format(timeLayout),
		CredentialID:         truncateCredentialID(identity.CredentialID),
		Mode:                 authenticationMode(handler.authentication.SecurityMode),
		Store:                validation.StoreName,
		ServerStateChecked:   validation.ServerStateChecked,
		UserStateChecked:     validation.CurrentUserChecked,
		ValidationDurationUS: validation.Duration.Microseconds(),
	}); err != nil {
		handler.logger.Printf("no fue posible responder identidad: %v", err)
	}
}

func authenticationMode(securityMode string) string {
	if securityMode == "session" {
		return "stateful"
	}
	return securityMode
}

func (handler *Handler) adminUsers(writer http.ResponseWriter, request *http.Request) {
	requestAuthentication, _ := auth.FromContext(request.Context())
	users, err := handler.userService.ListUsers(request.Context())
	if err != nil {
		handler.logger.Printf("no fue posible listar usuarios: %v", err)
		http.Error(writer, "No fue posible listar usuarios", http.StatusInternalServerError)
		return
	}

	userViews := make([]userViewModel, 0, len(users))
	for _, listedUser := range users {
		userViews = append(userViews, userViewModel{
			ID:       listedUser.ID,
			Name:     listedUser.Name,
			Email:    listedUser.Email,
			Role:     string(listedUser.Role),
			Active:   listedUser.Active,
			CanBlock: listedUser.ID != requestAuthentication.Identity.UserID,
		})
	}

	successMessage := ""
	switch request.URL.Query().Get("message") {
	case "blocked":
		switch handler.authentication.SecurityMode {
		case "session":
			successMessage = "Usuario bloqueado y sesiones revocadas"
		case "controlled":
			successMessage = "Usuario bloqueado; las credenciales anteriores quedan invalidadas por estado y versión"
		default:
			successMessage = "Usuario bloqueado; los JWT ya emitidos conservan validez hasta expirar"
		}
	case "unblocked":
		successMessage = "Usuario desbloqueado"
	}
	handler.render(writer, http.StatusOK, "admin_users", viewData{
		Title:          "Administración de usuarios",
		CurrentPage:    "admin",
		Users:          userViews,
		SuccessMessage: successMessage,
	}, request)
}

func (handler *Handler) blockUser(writer http.ResponseWriter, request *http.Request) {
	handler.setUserActive(writer, request, false)
}

func (handler *Handler) unblockUser(writer http.ResponseWriter, request *http.Request) {
	handler.setUserActive(writer, request, true)
}

func (handler *Handler) setUserActive(writer http.ResponseWriter, request *http.Request, active bool) {
	if !handler.parseProtectedForm(writer, request) {
		return
	}

	targetUserID, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if err != nil || targetUserID < 1 {
		http.Error(writer, "Usuario no encontrado", http.StatusNotFound)
		return
	}

	requestAuthentication, _ := auth.FromContext(request.Context())
	updatedUser, err := handler.userService.SetActive(
		request.Context(),
		requestAuthentication.Identity.UserID,
		targetUserID,
		active,
	)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrCannotBlockSelf):
			http.Error(writer, user.ErrCannotBlockSelf.Error(), http.StatusBadRequest)
		case errors.Is(err, user.ErrNotFound):
			http.Error(writer, "Usuario no encontrado", http.StatusNotFound)
		default:
			handler.logger.Printf("no fue posible cambiar estado de usuario: %v", err)
			http.Error(writer, "No fue posible cambiar el estado del usuario", http.StatusInternalServerError)
		}
		return
	}

	if handler.authentication.Revoker != nil {
		if err := handler.authentication.Revoker.RevokeUser(request.Context(), updatedUser.ID); err != nil {
			handler.logger.Printf("no fue posible revocar sesiones después de cambiar estado: %v", err)
			http.Error(writer, "El estado cambió, pero no fue posible revocar las sesiones", http.StatusInternalServerError)
			return
		}
	}

	message := "blocked"
	if active {
		message = "unblocked"
	}
	http.Redirect(writer, request, "/admin/users?message="+message, http.StatusSeeOther)
}

func (handler *Handler) parseProtectedForm(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBytes)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Formulario inválido", http.StatusBadRequest)
		return false
	}

	requestAuthentication, exists := auth.FromContext(request.Context())
	if !exists || !security.CSRFTokenMatches(requestAuthentication.CSRFToken, request.PostFormValue("csrf_token")) {
		http.Error(writer, "Token CSRF inválido", http.StatusForbidden)
		return false
	}

	return true
}

func passwordErrorMessage(err error) (string, bool) {
	switch {
	case errors.Is(err, user.ErrCurrentPasswordInvalid):
		return "La contraseña actual no es correcta", true
	case errors.Is(err, user.ErrNewPasswordRequired):
		return "La contraseña nueva es obligatoria", true
	case errors.Is(err, user.ErrPasswordConfirmation):
		return "La confirmación no coincide", true
	case errors.Is(err, user.ErrPasswordUnchanged):
		return "La contraseña nueva debe ser diferente", true
	case errors.Is(err, user.ErrUserUnavailable):
		return "El usuario no está disponible", true
	default:
		return "", false
	}
}

const timeLayout = "2006-01-02T15:04:05Z07:00"

func formatOptionalAPITime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timeLayout)
}
