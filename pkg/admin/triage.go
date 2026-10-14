package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// HandleCreateTriageRule allows the Sheriff to build a new ingestion interceptor rule
func (h *Handler) HandleCreateTriageRule(w http.ResponseWriter, r *http.Request) {
	var rule domain.AutoTriageRule // 🚀 FIX: Use the Pro Model
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	store := h.Store

	if err := store.CreateAutoTriageRule(r.Context(), &rule); err != nil {
		http.Error(w, "Failed to create rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

// HandleGetTriageRules lists the active interceptor rules for the UI
func (h *Handler) HandleGetTriageRules(w http.ResponseWriter, r *http.Request) {
	store := h.Store

	rules, err := store.GetAutoTriageRules(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// HandleDeleteTriageRule removes an interceptor rule
func (h *Handler) HandleDeleteTriageRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	ruleID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	store := h.Store

	if err := store.DeleteAutoTriageRule(r.Context(), ruleID); err != nil {
		http.Error(w, "Failed to delete rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Triage rule deleted successfully",
	})
}
