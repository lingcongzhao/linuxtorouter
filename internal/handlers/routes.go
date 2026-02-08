package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"linuxtorouter/internal/auth"
	"linuxtorouter/internal/middleware"
	"linuxtorouter/internal/models"
	"linuxtorouter/internal/services"
)

type RoutesHandler struct {
	templates      TemplateExecutor
	routeService   *services.IPRouteService
	netlinkService *services.NetlinkService
	userService    *auth.UserService
}

func NewRoutesHandler(templates TemplateExecutor, routeService *services.IPRouteService, netlinkService *services.NetlinkService, userService *auth.UserService) *RoutesHandler {
	return &RoutesHandler{
		templates:      templates,
		routeService:   routeService,
		netlinkService: netlinkService,
		userService:    userService,
	}
}

func (h *RoutesHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	table := r.URL.Query().Get("table")
	if table == "" {
		table = "main"
	}

	routes, err := h.routeService.ListRoutes(table)
	if err != nil {
		log.Printf("Failed to list routes: %v", err)
		routes = []models.Route{}
	}

	tables, _ := h.routeService.GetRoutingTables()

	interfaces, _ := h.netlinkService.ListInterfaces()
	var ifaceNames []string
	for _, iface := range interfaces {
		ifaceNames = append(ifaceNames, iface.Name)
	}

	data := map[string]interface{}{
		"Title":        "Routing Tables",
		"ActivePage":   "routes",
		"User":         user,
		"Routes":       routes,
		"CurrentTable": table,
		"Tables":       tables,
		"Interfaces":   ifaceNames,
	}

	if err := h.templates.ExecuteTemplate(w, "routes.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *RoutesHandler) GetRoutes(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	if table == "" {
		table = "main"
	}

	routes, err := h.routeService.ListRoutes(table)
	if err != nil {
		log.Printf("Failed to list routes: %v", err)
		routes = []models.Route{}
	}

	data := map[string]interface{}{
		"Routes":       routes,
		"CurrentTable": table,
	}

	if err := h.templates.ExecuteTemplate(w, "route_table.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *RoutesHandler) AddRoute(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if err := r.ParseForm(); err != nil {
		h.renderAlert(w, "error", "Invalid form data")
		return
	}

	metric, _ := strconv.Atoi(r.FormValue("metric"))

	input := models.RouteInput{
		Destination: strings.TrimSpace(r.FormValue("destination")),
		Gateway:     strings.TrimSpace(r.FormValue("gateway")),
		Interface:   strings.TrimSpace(r.FormValue("interface")),
		Metric:      metric,
		Table:       r.FormValue("table"),
	}

	if input.Destination == "" {
		h.renderAlert(w, "error", "Destination is required")
		return
	}

	if input.Gateway == "" && input.Interface == "" {
		h.renderAlert(w, "error", "Gateway or interface is required")
		return
	}

	if err := h.routeService.AddRoute(input); err != nil {
		log.Printf("Failed to add route: %v", err)
		h.renderAlert(w, "error", "Failed to add route: "+err.Error())
		return
	}

	h.userService.LogAction(&user.ID, "route_add",
		"Dest: "+input.Destination+", Gateway: "+input.Gateway+", Dev: "+input.Interface, getClientIP(r))
	h.renderAlert(w, "success", "Route added successfully")
}

func (h *RoutesHandler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	// Use query parameters for DELETE requests
	destination := r.URL.Query().Get("destination")
	gateway := r.URL.Query().Get("gateway")
	iface := r.URL.Query().Get("interface")
	table := r.URL.Query().Get("table")

	if destination == "" {
		h.renderAlert(w, "error", "Destination is required")
		return
	}

	if err := h.routeService.DeleteRoute(destination, gateway, iface, table); err != nil {
		log.Printf("Failed to delete route: %v", err)
		h.renderAlert(w, "error", "Failed to delete route: "+err.Error())
		return
	}

	h.userService.LogAction(&user.ID, "route_delete",
		"Dest: "+destination+", Table: "+table, getClientIP(r))
	h.renderAlert(w, "success", "Route deleted successfully")
}

func (h *RoutesHandler) SaveRoutes(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if err := h.routeService.SaveRoutes(); err != nil {
		log.Printf("Failed to save routes: %v", err)
		h.renderAlert(w, "error", "Failed to save routes: "+err.Error())
		return
	}

	h.userService.LogAction(&user.ID, "routes_save", "", getClientIP(r))
	h.renderAlert(w, "success", "Routes saved successfully")
}

func (h *RoutesHandler) renderAlert(w http.ResponseWriter, alertType, message string) {
	if alertType == "success" {
		w.Header().Set("HX-Trigger", "refresh")
	}
	data := map[string]interface{}{
		"Type":    alertType,
		"Message": message,
	}
	h.templates.ExecuteTemplate(w, "alert.html", data)
}
