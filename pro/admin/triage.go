// File: RiskRancher/pro/internal/admin/triage.go
package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models" // 🚀 FIX: Alias the Pro Models
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// HandleCreateTriageRule allows the Sheriff to build a new ingestion interceptor rule
func (h *ProHandler) HandleCreateTriageRule(w http.ResponseWriter, r *http.Request) {
	var rule proModels.AutoTriageRule // 🚀 FIX: Use the Pro Model
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	rule.WorkspaceID = 1

	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	if err := proStore.CreateAutoTriageRule(r.Context(), &rule); err != nil {
		http.Error(w, "Failed to create rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

// HandleGetTriageRules lists the active interceptor rules for the UI
func (h *ProHandler) HandleGetTriageRules(w http.ResponseWriter, r *http.Request) {
	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	rules, err := proStore.GetAutoTriageRules(r.Context(), 1)
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// HandleDeleteTriageRule removes an interceptor rule
func (h *ProHandler) HandleDeleteTriageRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	ruleID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	if err := proStore.DeleteAutoTriageRule(r.Context(), ruleID); err != nil {
		http.Error(w, "Failed to delete rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Triage rule deleted successfully",
	})
}
