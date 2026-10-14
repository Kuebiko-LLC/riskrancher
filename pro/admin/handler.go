package admin

import (
	"encoding/json"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type ProHandler struct {
	Store    domain.Store
	ProStore domain.Store // 🚀 FIX: Hold the Pro version of the store
}

// 🚀 NEW: Power the System Logs Tab
func (h *ProHandler) HandleGetLogs(w http.ResponseWriter, r *http.Request) {
	// Fetch the real audit logs using the method we added to pro_sqlite.go
	feed, _ := h.ProStore.GetGlobalActivityFeed(r.Context(), 100)

	// Wrap it in the pagination struct that admin.js expects
	json.NewEncoder(w).Encode(map[string]any{
		"feed":  feed,
		"total": len(feed),
		"page":  1,
		"limit": 100,
	})
}

func NewProHandler(store domain.Store) *ProHandler {
	return &ProHandler{
		Store:    store,
		ProStore: store.(domain.Store), // 🚀 FIX: Type assert it once at boot
	}
}

// HandleGetCISACatalog returns metadata about the current catalog for the UI
func (h *ProHandler) HandleGetCISACatalog(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Catalog Active"})
}
