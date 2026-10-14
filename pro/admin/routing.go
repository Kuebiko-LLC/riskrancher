package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// File: RiskRancher/pro/internal/admin/pro_handler.go

func (h *ProHandler) HandleCreateRoutingRule(w http.ResponseWriter, r *http.Request) {
	var rule domain.RoutingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rule.WorkspaceID = 1

	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	if err := proStore.CreateRoutingRule(r.Context(), &rule); err != nil {
		// 🚀 FIX: Log the actual SQLite error so we aren't flying blind!
		fmt.Println("🚨 SQLITE ERROR:", err)
		httpServerError(w, "db", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

func (h *ProHandler) HandleGetRoutingRules(w http.ResponseWriter, r *http.Request) {
	proStore := h.Store.(storage.ProStoreInterface)
	rules, err := proStore.GetRoutingRules(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}
	// 🚀 FIX: Actually return the rules to the HTMX/JS frontend
	json.NewEncoder(w).Encode(rules)
}

func (h *ProHandler) HandleDeleteRoutingRule(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	proStore := h.Store.(storage.ProStoreInterface)

	// 🚀 FIX: Wire up the delete
	if err := proStore.DeleteRoutingRule(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete rule", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
