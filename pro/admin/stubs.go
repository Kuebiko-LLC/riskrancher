// File: RiskRancher/pro/internal/admin/stubs.go
package admin

import "net/http"

// --- Service Accounts (API Keys) ---
func (h *ProHandler) HandleGetAPIKeys(w http.ResponseWriter, r *http.Request)   {}
func (h *ProHandler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {}
func (h *ProHandler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {}

// --- Integrations & Dashboards ---
func (h *ProHandler) HandleExecDashboardData(w http.ResponseWriter, r *http.Request)     {}
func (h *ProHandler) HandleGenerateBrandedReport(w http.ResponseWriter, r *http.Request) {}

// --- SUPPRESSION RULES STUBS ---

func (h *ProHandler) HandleGetSuppressionRules(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement DB fetch and UI render
	w.WriteHeader(http.StatusOK)
}

func (h *ProHandler) HandleCreateSuppressionRule(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement JSON parsing and DB insert
	w.WriteHeader(http.StatusCreated)
}

func (h *ProHandler) HandleDeleteSuppressionRule(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement DB delete
	w.WriteHeader(http.StatusOK)
}
