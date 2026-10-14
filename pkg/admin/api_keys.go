package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// API keys let scanners and pipelines push findings without a browser session.
// A key acts as the user who created it. The raw key is shown once, on creation.

func (h *Handler) HandleGetAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.Store.ListAPIKeys(r.Context())
	if err != nil {
		http.Error(w, "Failed to list API keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

type createAPIKeyRequest struct {
	Name        string `json:"name"`
	Permissions string `json:"permissions"` // ReadOnly, WriteOnly, FullAdmin
	ExpiresAt   string `json:"expires_at,omitempty"`
}

func (h *Handler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(auth.UserIDKey).(int)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Permissions == "" {
		req.Permissions = "FullAdmin"
	}
	key := domain.APIKey{Name: req.Name, Permissions: req.Permissions, CreatedBy: userID}
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "expires_at must be RFC 3339", http.StatusBadRequest)
			return
		}
		key.ExpiresAt = &t
	}
	raw, err := h.Store.CreateAPIKey(r.Context(), key)
	if err != nil {
		http.Error(w, "Failed to create API key: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"name": key.Name, "permissions": key.Permissions, "key": raw, "note": "shown once; store it now"})
}

func (h *Handler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid key id", http.StatusBadRequest)
		return
	}
	if err := h.Store.DeleteAPIKey(r.Context(), id); err != nil {
		http.Error(w, "Failed to revoke API key", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
