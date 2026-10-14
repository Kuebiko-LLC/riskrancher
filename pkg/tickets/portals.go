package tickets

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Bulk assignment and magic-link generation.
func (h *Handler) HandleBulkUpdate(w http.ResponseWriter, r *http.Request) {
	var req BulkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("🚨 API ERROR: Failed to decode JSON body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. The store must carry the workflow methods
	store := h.Store

	// 2. Execute the transaction
	batchToken, err := store.BulkUpdateStatusAndAssign(r.Context(), req.TicketIDs, req.Status, req.Assignee, req.Comment, req.Actor)
	if err != nil {
		// 🚀 If it fails here, SQLite is rejecting our query!
		log.Printf("🚨 DATABASE TRANSACTION ERROR in BulkUpdate: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Return the newly generated batch token back to the UI
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"batch_token": batchToken,
	})
}

// portalBatch resolves the link in the path. The link is the authorization.
func (h *Handler) portalBatch(w http.ResponseWriter, r *http.Request) (*domain.MagicBatch, bool) {
	batch, err := h.Store.GetMagicBatch(r.Context(), r.PathValue("token"))
	if err != nil {
		http.Error(w, "This link is not valid: "+err.Error(), http.StatusNotFound)
		return nil, false
	}
	return batch, true
}

// inBatch keeps a request to the findings its link covers.
func inBatch(batch *domain.MagicBatch, requested []int) []int {
	if len(requested) == 0 {
		return batch.TicketIDs
	}
	allowed := map[int]bool{}
	for _, id := range batch.TicketIDs {
		allowed[id] = true
	}
	var ids []int
	for _, id := range requested {
		if allowed[id] {
			ids = append(ids, id)
		}
	}
	return ids
}

// HandleMagicLink is the owner's view: the findings this link covers.
func (h *Handler) HandleMagicLink(w http.ResponseWriter, r *http.Request) {
	batch, ok := h.portalBatch(w, r)
	if !ok {
		return
	}
	tickets, err := h.Store.TicketsByIDs(r.Context(), batch.TicketIDs)
	if err != nil {
		http.Error(w, "Failed to load findings", http.StatusInternalServerError)
		return
	}
	assignee := ""
	if len(tickets) > 0 {
		assignee = tickets[0].Assignee
	}
	defaultDays := 30
	if cfg, err := h.Store.GetAppConfig(r.Context()); err == nil && cfg.DefaultExtensionDays > 0 {
		defaultDays = cfg.DefaultExtensionDays
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"token": batch.Token, "assignee": assignee, "tickets": tickets, "default_extension_days": defaultDays})
}

// HandleMagicLinkSubmit is the owner saying a finding is fixed, with evidence.
func (h *Handler) HandleMagicLinkSubmit(w http.ResponseWriter, r *http.Request) {
	batch, ok := h.portalBatch(w, r)
	if !ok {
		return
	}
	var req struct {
		PatchEvidence string `json:"patch_evidence"`
		TicketIDs     []int  `json:"ticket_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	ids := inBatch(batch, req.TicketIDs)
	if len(ids) == 0 {
		http.Error(w, "No findings on this link match the request", http.StatusBadRequest)
		return
	}
	if err := h.Store.SubmitPortalFix(r.Context(), ids, req.PatchEvidence, portalActor(h, r, batch)); err != nil {
		http.Error(w, "Failed to record the fix", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleSubmitRiskRequest is the owner asking for more time or for the risk to be accepted.
func (h *Handler) HandleSubmitRiskRequest(w http.ResponseWriter, r *http.Request) {
	batch, ok := h.portalBatch(w, r)
	if !ok {
		return
	}
	var req struct {
		Type      string `json:"type"`
		Rationale string `json:"rationale"`
		TicketIDs []int  `json:"ticket_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Rationale == "" {
		http.Error(w, "A rationale is required", http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		req.Type = "Risk Acceptance"
	}
	ids := inBatch(batch, req.TicketIDs)
	if len(ids) == 0 {
		http.Error(w, "No findings on this link match the request", http.StatusBadRequest)
		return
	}
	if err := h.Store.RequestRiskException(r.Context(), ids, req.Type, req.Rationale, portalActor(h, r, batch)); err != nil {
		http.Error(w, "Failed to record the request", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleMagistrateReview is the approver's decision on the findings this link covers.
func (h *Handler) HandleMagistrateReview(w http.ResponseWriter, r *http.Request) {
	batch, ok := h.portalBatch(w, r)
	if !ok {
		return
	}
	var req MagistrateReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if req.Action == "Deny" && req.Comment == "" {
		http.Error(w, "A comment is required to deny", http.StatusBadRequest)
		return
	}
	actor := req.Actor
	if actor == "" {
		actor = "Risk approver"
	}
	err := h.Store.ReviewRiskRequest(r.Context(), batch.TicketIDs, req.Action, actor, req.Comment, req.ExtensionDays)
	if errors.Is(err, datastore.ErrExtensionCapReached) {
		http.Error(w, "This finding has had every extension its SLA policy allows", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "Failed to record the decision: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// portalActor names who acted through a link: the owner the findings are
// assigned to, which is who the link was minted for.
func portalActor(h *Handler, r *http.Request, batch *domain.MagicBatch) string {
	if len(batch.TicketIDs) > 0 {
		if t, err := h.Store.GetTicketByID(r.Context(), batch.TicketIDs[0]); err == nil && t.Assignee != "" && t.Assignee != "Unassigned" {
			return t.Assignee
		}
	}
	return "portal:" + batch.Token[:8]
}

// Extract the ticket IDs from the JSON payload and pass them to the store
func (h *Handler) HandleWranglerReject(w http.ResponseWriter, r *http.Request) {
	batch, ok := h.portalBatch(w, r)
	if !ok {
		return
	}
	var req struct {
		TicketIDs []int  `json:"ticket_ids"`
		Reason    string `json:"reason"`
		Comment   string `json:"comment"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("🚨 API ERROR: Failed to decode JSON: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("🚨 INCOMING REJECT REQUEST: Received %d ticket IDs. Reason: %s", len(req.TicketIDs), req.Reason)

	// If the array is empty, block the request so we don't silently fail!
	if len(req.TicketIDs) == 0 {
		log.Println("⚠️ WARNING: The frontend sent ZERO tickets! (You need to hard-refresh your browser cache)")
		http.Error(w, "No tickets selected", http.StatusBadRequest)
		return
	}

	// Assuming the Store has been updated to include the Pro interface methods
	store := h.Store

	ids := inBatch(batch, req.TicketIDs)
	if len(ids) == 0 {
		http.Error(w, "No findings on this link match the request", http.StatusBadRequest)
		return
	}
	if err := store.RejectTicketFromWrangler(r.Context(), ids, req.Reason, req.Comment); err != nil {
		http.Error(w, "Failed to reject tickets", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RejectRequest defines the expected JSON payload for returning tickets
type RejectRequest struct {
	TicketIDs []int  `json:"ticket_ids"`
	Reason    string `json:"reason"`
	Comment   string `json:"comment"`
}

// RejectTicketsHandler allows a Wrangler to kick a ticket back to Security (The "Escape Hatch")
