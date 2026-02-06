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

	"github.com/go-chi/chi/v5"
)

type RulesHandler struct {
	templates      TemplateExecutor
	ruleService    *services.IPRuleService
	routeService   *services.IPRouteService
	netlinkService *services.NetlinkService
	userService    *auth.UserService
}

func NewRulesHandler(templates TemplateExecutor, ruleService *services.IPRuleService, routeService *services.IPRouteService, netlinkService *services.NetlinkService, userService *auth.UserService) *RulesHandler {
	return &RulesHandler{
		templates:      templates,
		ruleService:    ruleService,
		routeService:   routeService,
		netlinkService: netlinkService,
		userService:    userService,
	}
}

func (h *RulesHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	rules, err := h.ruleService.ListRules()
	if err != nil {
		log.Printf("Failed to list rules: %v", err)
		rules = []models.IPRule{}
	}

	tables, _ := h.routeService.GetRoutingTables()
	interfaces, _ := h.netlinkService.ListInterfaces()

	var ifaceNames []string
	for _, iface := range interfaces {
		ifaceNames = append(ifaceNames, iface.Name)
	}

	data := map[string]interface{}{
		"Title":      "IP Rules",
		"ActivePage": "rules",
		"User":       user,
		"Rules":      rules,
		"Tables":     tables,
		"Interfaces": ifaceNames,
	}

	if err := h.templates.ExecuteTemplate(w, "rules.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *RulesHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.ruleService.ListRules()
	if err != nil {
		log.Printf("Failed to list rules: %v", err)
		rules = []models.IPRule{}
	}

	data := map[string]interface{}{
		"Rules": rules,
	}

	if err := h.templates.ExecuteTemplate(w, "rule_table.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *RulesHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if err := r.ParseForm(); err != nil {
		h.renderAlert(w, "error", "Invalid form data")
		return
	}

	priority, _ := strconv.Atoi(r.FormValue("priority"))

	input := models.IPRuleInput{
		Priority: priority,
		From:     strings.TrimSpace(r.FormValue("from")),
		To:       strings.TrimSpace(r.FormValue("to")),
		FWMark:   strings.TrimSpace(r.FormValue("fwmark")),
		IIF:      strings.TrimSpace(r.FormValue("iif")),
		OIF:      strings.TrimSpace(r.FormValue("oif")),
		Table:    r.FormValue("table"),
		Not:      r.FormValue("not") == "on",
	}

	if input.Table == "" {
		h.renderAlert(w, "error", "Routing table is required")
		return
	}

	if err := h.ruleService.AddRule(input); err != nil {
		log.Printf("Failed to add rule: %v", err)
		h.renderAlert(w, "error", "Failed to add rule: "+err.Error())
		return
	}

	details := "Table: " + input.Table
	if input.From != "" {
		details += ", From: " + input.From
	}
	if input.To != "" {
		details += ", To: " + input.To
	}
	h.userService.LogAction(&user.ID, "rule_add", details, getClientIP(r))
	h.renderAlert(w, "success", "Rule added successfully")
}

func (h *RulesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	priorityStr := chi.URLParam(r, "priority")
	priority, err := strconv.Atoi(priorityStr)
	if err != nil {
		h.renderAlert(w, "error", "Invalid priority")
		return
	}

	if err := h.ruleService.DeleteByPriority(priority); err != nil {
		log.Printf("Failed to delete rule: %v", err)
		h.renderAlert(w, "error", "Failed to delete rule: "+err.Error())
		return
	}

	h.userService.LogAction(&user.ID, "rule_delete", "Priority: "+priorityStr, getClientIP(r))
	h.renderAlert(w, "success", "Rule deleted successfully")
}

func (h *RulesHandler) SaveRules(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if err := h.ruleService.SaveRules(); err != nil {
		log.Printf("Failed to save rules: %v", err)
		h.renderAlert(w, "error", "Failed to save rules: "+err.Error())
		return
	}

	h.userService.LogAction(&user.ID, "rules_save", "", getClientIP(r))
	h.renderAlert(w, "success", "Rules saved successfully")
}

func (h *RulesHandler) renderAlert(w http.ResponseWriter, alertType, message string) {
	data := map[string]interface{}{
		"Type":    alertType,
		"Message": message,
	}
	h.templates.ExecuteTemplate(w, "alert.html", data)
}
