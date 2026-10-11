package admin

import (
	"encoding/json"
	"net/http"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// HandleSyncCISAKEV accepts a multipart file upload of the official CISA JSON catalog
func (h *ProHandler) HandleSyncCISAKEV(w http.ResponseWriter, r *http.Request) {
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
	var feed proModels.CISAFeed
	if err := json.NewDecoder(file).Decode(&feed); err != nil {
		http.Error(w, "Invalid CISA JSON format", http.StatusBadRequest)
		return
	}

	if len(feed.Vulnerabilities) == 0 {
		http.Error(w, "No vulnerabilities found in the uploaded file", http.StatusBadRequest)
		return
	}

	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "Enterprise storage driver not loaded", http.StatusInternalServerError)
		return
	}

	// Execute the Air-Gapped Sync
	if err := proStore.SyncCISACatalog(r.Context(), &feed); err != nil {
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
