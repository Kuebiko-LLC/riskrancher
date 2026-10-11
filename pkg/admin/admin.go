package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func (h *Handler) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.Store.GetAppConfig(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(config)
}

func (h *Handler) HandleExportState(w http.ResponseWriter, r *http.Request) {
	state, err := h.Store.ExportSystemState(r.Context())
	if err != nil {
		http.Error(w, "Failed to generate system export", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=RiskRancher_export.json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(state); err != nil {
		// Note: We can't change the HTTP status code here because we've already started streaming,
		// but we can log the error if the stream breaks.
		_ = err
	}
}

func (h *Handler) HandleGetLogs(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	limit := 15
	offset := (page - 1) * limit

	feed, total, err := h.Store.GetPaginatedActivityFeed(r.Context(), filter, limit, offset)
	if err != nil {
		http.Error(w, "Failed to load logs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"feed":  feed,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}
