package admin

import (
	"encoding/json"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// HandleSyncCISAKEV accepts a multipart file upload of the official CISA JSON catalog
func (h *Handler) HandleSyncCISAKEV(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form (Max 50MB upload size)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("cisa_catalog_file")
	if err != nil {
		http.Error(w, "Missing 'cisa_catalog_file' in request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Decode the JSON file directly into our struct
	var feed domain.CISAFeed
	if err := json.NewDecoder(file).Decode(&feed); err != nil {
		http.Error(w, "Invalid CISA JSON format", http.StatusBadRequest)
		return
	}

	if len(feed.Vulnerabilities) == 0 {
		http.Error(w, "No vulnerabilities found in the uploaded file", http.StatusBadRequest)
		return
	}

	store := h.Store

	// Execute the Air-Gapped Sync
	if err := store.SyncCISACatalog(r.Context(), &feed); err != nil {
		http.Error(w, "Database sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":          "success",
		"message":         "CISA KEV Catalog synced successfully",
		"vulnerabilities": len(feed.Vulnerabilities),
	})
}

// HandleGetCISACatalog returns metadata about the current catalog for the UI
func (h *Handler) HandleGetCISACatalog(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Catalog Active"})
}
