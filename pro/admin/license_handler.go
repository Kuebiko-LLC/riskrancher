// File: RiskRancher/pro/internal/admin/license_handler.go
package admin

import (
	"encoding/json"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pro/license"
)

type ActivationRequest struct {
	LicenseKey string `json:"license_key"`
}

// HandleActivateLicense processes the frontend form submission
func (h *ProHandler) HandleActivateLicense(manager *license.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ActivationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// 1. Mathematically verify the token in real-time
		if err := manager.Activate(req.LicenseKey); err != nil {
			// If it fails, return the exact error (e.g., "Expired", "Tampered") to the UI
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// 2. Success! Save it to SQLite so it survives reboots
		// 🚀 THE FIX: Use h.ProStore instead of h.Store
		if err := h.ProStore.SaveLicenseKey(r.Context(), req.LicenseKey); err != nil {
			// Even if DB fails, the in-memory manager is active, so we just log the error and let them in
			http.Error(w, `{"error": "Activated, but failed to persist to disk"}`, http.StatusInternalServerError)
			return
		}

		// 3. Return 200 OK to trigger the frontend redirect to /admin
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}
}
