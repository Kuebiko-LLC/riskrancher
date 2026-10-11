package analytics

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) HandleGetAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := h.Store.GetAnalyticsSummary(r.Context())
	if err != nil {
		http.Error(w, "Failed to generate analytics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
