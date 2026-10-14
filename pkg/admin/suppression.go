package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Suppression rules are the false-positive log: a finding logged here lands
// closed as False Positive on every scan after, on that asset.

func (h *Handler) HandleGetSuppressionRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Store.ListSuppressionRules(r.Context())
	if err != nil {
		http.Error(w, "Failed to list suppression rules", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// A rule names the finding either by its dedupe hash, or by the source, asset
// and title the hash is made of.
type createSuppressionRequest struct {
	DedupeHash      string `json:"dedupe_hash"`
	Source          string `json:"source"`
	AssetIdentifier string `json:"asset_identifier"`
	Title           string `json:"title"`
	Rationale       string `json:"rationale"`
}

func (h *Handler) HandleCreateSuppressionRule(w http.ResponseWriter, r *http.Request) {
	var req createSuppressionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.DedupeHash == "" {
		if req.Source == "" || req.AssetIdentifier == "" || req.Title == "" {
			http.Error(w, "give dedupe_hash, or source, asset_identifier and title", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256([]byte(req.Source + "|" + req.AssetIdentifier + "|" + req.Title))
		req.DedupeHash = hex.EncodeToString(sum[:])
	}
	if req.AssetIdentifier == "" || req.Rationale == "" {
		http.Error(w, "asset_identifier and rationale are required", http.StatusBadRequest)
		return
	}
	actor := "unknown"
	if id, ok := r.Context().Value(auth.UserIDKey).(int); ok {
		if u, err := h.Store.GetUserByID(r.Context(), id); err == nil {
			actor = u.Email
		}
	}
	rule := domain.SuppressionRule{DedupeHash: req.DedupeHash, AssetIdentifier: req.AssetIdentifier, Rationale: req.Rationale, Actor: actor}
	if err := h.Store.CreateSuppressionRule(r.Context(), &rule); err != nil {
		http.Error(w, "Failed to log the false positive: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

func (h *Handler) HandleDeleteSuppressionRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	if err := h.Store.DeleteSuppressionRule(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete suppression rule", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
