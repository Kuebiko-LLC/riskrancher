package admin

import (
	"encoding/json"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"net/http"
	"strconv"
)

// HandleUpdateFinding edits a finding's report-grade fields (severity, text,
// CVSS, CWE, business impact). Owner-gated. PUT /api/findings/{id}
func (h *ProHandler) HandleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid finding id", http.StatusBadRequest)
		return
	}
	if !h.ownsTicketOrSheriff(r, id) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Severity       string  `json:"severity"`
		Description    string  `json:"description"`
		Remediation    string  `json:"remediation"`
		CVSSVector     string  `json:"cvss_vector"`
		CVSSScore      float64 `json:"cvss_score"`
		CWE            string  `json:"cwe"`
		BusinessImpact string  `json:"business_impact"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		http.Error(w, "invalid severity", http.StatusBadRequest)
		return
	}
	if err := h.ProStore.UpdateFindingDetails(r.Context(), id, domain.FindingDetails{
		Severity: req.Severity, Description: req.Description, Remediation: req.Remediation,
		CVSSVector: req.CVSSVector, CVSSScore: req.CVSSScore, CWE: req.CWE, BusinessImpact: req.BusinessImpact,
	}); err != nil {
		httpServerError(w, "UpdateFindingDetails", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}
