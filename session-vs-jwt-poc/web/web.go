package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"session-vs-jwt-poc/internal/auth"
	"session-vs-jwt-poc/internal/user"
)

const maxFormBytes int64 = 16 << 10

//go:embed static/app.css templates/*.html
var assets embed.FS

type AppInfo struct {
	Method     string
	InstanceID string
}

type Authentication struct {
	Issuer             auth.CredentialIssuer
	Validator          auth.CredentialValidator
	Revoker            auth.CredentialRevoker
	Transport          auth.CredentialTransport
	CSRFTransport      auth.CSRFTokenTransport
	SecurityMode       string
	Validation         auth.ValidationMetadata
	UsesIdleExpiration bool
}

type Handler struct {
	appInfo        AppInfo
	userService    *user.Service
	logger         *log.Logger
	templates      map[string]*template.Template
	authentication *Authentication
}

type viewData struct {
	Title                 string
	CurrentPage           string
	Method                string
	InstanceID            string
	Email                 string
	ErrorMessage          string
	SuccessMessage        string
	Credential            *credentialViewModel
	Identity              *identityViewModel
	Users                 []userViewModel
	ResponseState         string
	CSRFToken             string
	Authenticated         bool
	IsAdmin               bool
	AuthenticationEnabled bool
	SecurityMode          string
	Validation            auth.ValidationMetadata
	ValidationDuration    string
	UsesIdleExpiration    bool
}

type credentialViewModel struct {
	Name  string
	Email string
	Role  string
}

type identityViewModel struct {
	UserID                int64
	Name                  string
	Email                 string
	Role                  string
	AuthenticatedAt       string
	IdleExpiresAt         string
	AbsoluteExpiresAt     string
	IdleTimeRemaining     string
	AbsoluteTimeRemaining string
	AuthenticationMethod  string
	CredentialID          string
	InstanceID            string
	HasIdleExpiration     bool
}

type userViewModel struct {
	ID       int64
	Name     string
	Email    string
	Role     string
	Active   bool
	CanBlock bool
}

func NewHandler(appInfo AppInfo, userService *user.Service, logger *log.Logger, authentication *Authentication) (http.Handler, error) {
	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	staticFiles, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("cargar archivos estáticos: %w", err)
	}

	handler := &Handler{
		appInfo:        appInfo,
		userService:    userService,
		logger:         logger,
		templates:      templates,
		authentication: authentication,
	}

	mux := handler.routes(staticFiles)
	return securityHeaders(mux), nil
}

func (handler *Handler) render(writer http.ResponseWriter, statusCode int, page string, data viewData, request *http.Request) {
	pageTemplate, exists := handler.templates[page]
	if !exists {
		handler.logger.Printf("template no registrado: %s", page)
		http.Error(writer, "No fue posible mostrar la página", http.StatusInternalServerError)
		return
	}

	data.Method = handler.appInfo.Method
	data.InstanceID = handler.appInfo.InstanceID
	data.AuthenticationEnabled = handler.authentication != nil
	if handler.authentication != nil {
		data.SecurityMode = handler.authentication.SecurityMode
		data.Validation = handler.authentication.Validation
		data.UsesIdleExpiration = handler.authentication.UsesIdleExpiration
	}
	if requestAuthentication, exists := auth.FromContext(request.Context()); exists {
		data.Authenticated = true
		data.IsAdmin = requestAuthentication.Identity.Role == user.RoleAdmin
		data.CSRFToken = requestAuthentication.CSRFToken
		data.Identity = identityView(requestAuthentication.Identity)
		data.Validation = requestAuthentication.Validation
		data.ValidationDuration = formatValidationDuration(requestAuthentication.Validation.Duration)
	}

	var renderedPage bytes.Buffer
	if err := pageTemplate.ExecuteTemplate(&renderedPage, "layout.html", data); err != nil {
		handler.logger.Printf("no fue posible renderizar %s: %v", page, err)
		http.Error(writer, "No fue posible mostrar la página", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(statusCode)
	if _, err := renderedPage.WriteTo(writer); err != nil {
		handler.logger.Printf("no fue posible enviar %s: %v", page, err)
	}
}

func loadTemplates() (map[string]*template.Template, error) {
	pageNames := []string{"home", "login", "credential_result", "dashboard", "password", "admin_users"}
	templates := make(map[string]*template.Template, len(pageNames))

	for _, pageName := range pageNames {
		pageTemplate, err := template.ParseFS(
			assets,
			"templates/layout.html",
			"templates/"+pageName+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("cargar template %s: %w", pageName, err)
		}
		templates[pageName] = pageTemplate
	}

	return templates, nil
}

func identityView(identity auth.Identity) *identityViewModel {
	now := time.Now().UTC()
	return &identityViewModel{
		UserID:                identity.UserID,
		Name:                  identity.Name,
		Email:                 identity.Email,
		Role:                  string(identity.Role),
		AuthenticatedAt:       formatTime(identity.AuthenticatedAt),
		IdleExpiresAt:         formatTime(identity.IdleExpiresAt),
		AbsoluteExpiresAt:     formatTime(identity.ExpiresAt),
		IdleTimeRemaining:     formatRemaining(identity.IdleExpiresAt.Sub(now)),
		AbsoluteTimeRemaining: formatRemaining(identity.ExpiresAt.Sub(now)),
		AuthenticationMethod:  identity.AuthenticationMethod,
		CredentialID:          truncateCredentialID(identity.CredentialID),
		InstanceID:            identity.InstanceID,
		HasIdleExpiration:     !identity.IdleExpiresAt.IsZero(),
	}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func formatRemaining(remaining time.Duration) string {
	if remaining < 0 {
		remaining = 0
	}
	return remaining.Round(time.Second).String()
}

func formatValidationDuration(duration time.Duration) string {
	if duration < time.Microsecond {
		return "<1 µs"
	}
	if duration < time.Millisecond {
		return fmt.Sprintf("%d µs", duration.Round(time.Microsecond).Microseconds())
	}
	return fmt.Sprintf("%.2f ms", float64(duration.Round(10*time.Microsecond))/float64(time.Millisecond))
}

func truncateCredentialID(credentialID string) string {
	if len(credentialID) <= 10 {
		return credentialID
	}
	return credentialID[:10] + "…"
}
