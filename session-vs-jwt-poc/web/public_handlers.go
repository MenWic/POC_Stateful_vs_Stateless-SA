package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

type healthResponse struct {
	Status     string `json:"status"`
	Method     string `json:"method"`
	InstanceID string `json:"instance"`
}

func (handler *Handler) home(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusOK, "home", viewData{
		Title:       "Inicio",
		CurrentPage: "home",
	}, request)
}

func (handler *Handler) loginForm(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusOK, "login", viewData{
		Title:          "Iniciar sesión",
		CurrentPage:    "login",
		SuccessMessage: loginReasonMessage(request.URL.Query().Get("reason")),
	}, request)
}

func (handler *Handler) login(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBytes)
	if err := request.ParseForm(); err != nil {
		handler.render(writer, http.StatusBadRequest, "login", viewData{
			Title:        "Iniciar sesión",
			CurrentPage:  "login",
			ErrorMessage: "No fue posible procesar el formulario",
		}, request)
		return
	}

	email := user.NormalizeEmail(request.PostFormValue("email"))
	validatedCredentials, err := handler.userService.Authenticate(
		request.Context(),
		email,
		request.PostFormValue("password"),
	)
	if errors.Is(err, user.ErrInvalidCredentials) {
		handler.render(writer, http.StatusUnauthorized, "login", viewData{
			Title:        "Iniciar sesión",
			CurrentPage:  "login",
			Email:        email,
			ErrorMessage: "Credenciales inválidas o usuario no disponible",
		}, request)
		return
	}
	if err != nil {
		handler.logger.Printf("no fue posible validar credenciales: %v", err)
		handler.render(writer, http.StatusInternalServerError, "login", viewData{
			Title:        "Iniciar sesión",
			CurrentPage:  "login",
			Email:        email,
			ErrorMessage: "No fue posible validar las credenciales en este momento",
		}, request)
		return
	}

	if handler.authentication == nil {
		handler.render(writer, http.StatusOK, "credential_result", viewData{
			Title:         "Credenciales válidas",
			CurrentPage:   "login",
			ResponseState: "Las credenciales son correctas, pero esta respuesta no crea ni conserva autenticación",
			Credential: &credentialViewModel{
				Name:  validatedCredentials.Name,
				Email: validatedCredentials.Email,
				Role:  string(validatedCredentials.Role),
			},
		}, request)
		return
	}

	previousCredential, previousCredentialErr := handler.authentication.Transport.Read(request)
	if previousCredentialErr == nil && handler.authentication.Revoker != nil {
		// La credencial anterior se invalida cuando el modo configurado soporta revocación
		if err := handler.authentication.Revoker.Revoke(request.Context(), previousCredential); err != nil {
			handler.logger.Printf("no fue posible revocar la sesión anterior durante login: %v", err)
			http.Error(writer, "No fue posible iniciar sesión", http.StatusInternalServerError)
			return
		}
	} else if previousCredentialErr != nil && !errors.Is(previousCredentialErr, auth.ErrMissingCredential) {
		handler.authentication.Transport.Clear(writer)
	}

	issuedCredential, err := handler.authentication.Issuer.Issue(request.Context(), validatedCredentials)
	if err != nil {
		handler.logger.Printf("no fue posible crear la credencial: %v", err)
		http.Error(writer, "No fue posible iniciar sesión", http.StatusInternalServerError)
		return
	}
	if handler.authentication.CSRFTransport != nil {
		if _, err := handler.authentication.CSRFTransport.Issue(writer, issuedCredential.ExpiresAt); err != nil {
			handler.logger.Printf("no fue posible crear protección CSRF: %v", err)
			http.Error(writer, "No fue posible iniciar sesión", http.StatusInternalServerError)
			return
		}
	}
	handler.authentication.Transport.Write(writer, issuedCredential)
	http.Redirect(writer, request, "/dashboard?message=login", http.StatusSeeOther)
}

func (handler *Handler) health(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(writer).Encode(healthResponse{
		Status:     "ok",
		Method:     handler.appInfo.Method,
		InstanceID: handler.appInfo.InstanceID,
	}); err != nil {
		handler.logger.Printf("no fue posible generar la respuesta de salud: %v", err)
	}
}

func loginReasonMessage(reason string) string {
	switch reason {
	case "idle":
		return "Tu sesión expiró por inactividad"
	case "absolute":
		return "Tu sesión alcanzó su duración máxima"
	case "revoked":
		return "Tu credencial fue revocada"
	case "blocked":
		return "Tu cuenta está bloqueada"
	case "logout":
		return "Sesión cerrada correctamente"
	case "password":
		return "Tu contraseña cambió y debes iniciar sesión nuevamente"
	case "invalid":
		return "La credencial no existe en esta instancia o ya no es válida"
	case "expired":
		return "Tu token expiró"
	case "required":
		return "Debes iniciar sesión para acceder"
	default:
		return ""
	}
}
