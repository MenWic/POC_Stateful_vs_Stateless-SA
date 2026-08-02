package web

import (
	"io/fs"
	"net/http"
)

func (handler *Handler) routes(staticFiles fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))
	mux.Handle("GET /{$}", handler.optionalAuthentication(http.HandlerFunc(handler.home)))
	mux.Handle("GET /login", handler.optionalAuthentication(http.HandlerFunc(handler.loginForm)))
	mux.HandleFunc("POST /login", handler.login)
	mux.HandleFunc("GET /health", handler.health)

	if handler.authentication == nil {
		mux.HandleFunc("GET /dashboard", handler.dashboardUnavailable)
		mux.HandleFunc("GET /account/password", handler.passwordUnavailable)
		mux.HandleFunc("POST /account/password", handler.passwordUnavailable)
		mux.HandleFunc("GET /admin/users", handler.adminUsersUnavailable)
		mux.HandleFunc("GET /api/me", handler.apiMeUnavailable)
		return mux
	}

	requirePageAuthentication := handler.requireAuthentication(false)
	requireAPIAuthentication := handler.requireAuthentication(true)
	mux.Handle("GET /dashboard", requirePageAuthentication(http.HandlerFunc(handler.dashboard)))
	mux.Handle("GET /account/password", requirePageAuthentication(http.HandlerFunc(handler.passwordForm)))
	mux.Handle("POST /account/password", requirePageAuthentication(http.HandlerFunc(handler.changePassword)))
	mux.Handle("POST /logout", requirePageAuthentication(http.HandlerFunc(handler.logout)))
	mux.Handle("GET /api/me", requireAPIAuthentication(http.HandlerFunc(handler.apiMe)))
	mux.Handle("GET /admin/users", requirePageAuthentication(handler.requireAdmin(http.HandlerFunc(handler.adminUsers))))
	mux.Handle("POST /admin/users/{id}/block", requirePageAuthentication(handler.requireAdmin(http.HandlerFunc(handler.blockUser))))
	mux.Handle("POST /admin/users/{id}/unblock", requirePageAuthentication(handler.requireAdmin(http.HandlerFunc(handler.unblockUser))))

	return mux
}
