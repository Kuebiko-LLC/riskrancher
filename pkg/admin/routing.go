package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (h *Handler) HandleCreateRoutingRule(w http.ResponseWriter, r *http.Request) {
	var rule domain.RoutingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	store := h.Store

	if err := store.CreateRoutingRule(r.Context(), &rule); err != nil {
		// FIX: Log the actual SQLite error so we aren't flying blind!
		fmt.Println("SQLITE ERROR:", err)
		httpServerError(w, "db", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

func (h *Handler) HandleGetRoutingRules(w http.ResponseWriter, r *http.Request) {
	store := h.Store
	rules, err := store.GetRoutingRules(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}
	// FIX: Actually return the rules to the HTMX/JS frontend
	json.NewEncoder(w).Encode(rules)
}

func (h *Handler) HandleDeleteRoutingRule(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	store := h.Store

	// FIX: Wire up the delete
	if err := store.DeleteRoutingRule(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete rule", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
