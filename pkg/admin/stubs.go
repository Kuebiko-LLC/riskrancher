package admin

import "net/http"

// --- Service Accounts (API Keys) ---
func (h *Handler) HandleGetAPIKeys(w http.ResponseWriter, r *http.Request)   {}
func (h *Handler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {}
func (h *Handler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {}

// --- Integrations & Dashboards ---
func (h *Handler) HandleExecDashboardData(w http.ResponseWriter, r *http.Request) {}

// HandleGenerateBrandedReport, HandleGetPentestReport, and
// HandleListPentestReports are implemented in reports.go.

// --- SUPPRESSION RULES STUBS ---

func (h *Handler) HandleGetSuppressionRules(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement DB fetch and UI render
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HandleCreateSuppressionRule(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement JSON parsing and DB insert
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) HandleDeleteSuppressionRule(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement DB delete
	w.WriteHeader(http.StatusOK)
}
