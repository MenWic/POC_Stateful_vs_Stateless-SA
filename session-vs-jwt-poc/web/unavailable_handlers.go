package web

import "net/http"

func (handler *Handler) dashboardUnavailable(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusUnauthorized, "dashboard", viewData{
		Title:         "Dashboard",
		CurrentPage:   "dashboard",
		ResponseState: "Esta ruta requiere una estrategia de autenticación configurada",
	}, request)
}

func (handler *Handler) passwordUnavailable(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusUnauthorized, "password", viewData{
		Title:         "Cambio de contraseña",
		CurrentPage:   "password",
		ResponseState: "El cambio de contraseña requiere identificar al usuario mediante autenticación real",
	}, request)
}

func (handler *Handler) adminUsersUnavailable(writer http.ResponseWriter, request *http.Request) {
	handler.render(writer, http.StatusUnauthorized, "admin_users", viewData{
		Title:         "Administración de usuarios",
		CurrentPage:   "admin",
		ResponseState: "La lista administrativa requiere autenticación y autorización reales",
	}, request)
}

func (handler *Handler) apiMeUnavailable(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusUnauthorized)
	if _, err := writer.Write([]byte("{\"error\":\"autenticación requerida\"}\n")); err != nil {
		handler.logger.Printf("no fue posible responder API sin autenticación: %v", err)
	}
}
