// File: RiskRancher/pro/internal/tickets/magic_handler.go
package tickets

import (
	"encoding/json"
	"log"
	"net/http"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

type ProHandler struct {
	Store core.Store
}

func NewProHandler(store core.Store) *ProHandler {
	return &ProHandler{Store: store}
}

type MagistrateReviewRequest struct {
	Action        string `json:"action"`
	Actor         string `json:"actor"`
	Comment       string `json:"comment"`
	ExtensionDays int    `json:"extension_days"`
}

type BulkUpdateRequest struct {
	TicketIDs []int  `json:"ticket_ids"`
	Status    string `json:"status"`
	Comment   string `json:"comment"`
	Assignee  string `json:"assignee"`
	Actor     string `json:"actor"`
}

// Bulk assignment and magic-link generation.
func (h *ProHandler) HandleBulkUpdate(w http.ResponseWriter, r *http.Request) {
	var req BulkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("🚨 API ERROR: Failed to decode JSON body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. The store must carry the workflow methods
	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		// 🚀 If it fails here, we know main.go didn't inject the database correctly
		log.Printf("🚨 CRITICAL INIT ERROR: Store is of type %T, which does not implement ProStoreInterface!", h.Store)
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	// 2. Execute the transaction
	batchToken, err := proStore.BulkUpdateStatusAndAssign(r.Context(), req.TicketIDs, req.Status, req.Assignee, req.Comment, req.Actor)
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

func (h *ProHandler) HandleMagicLink(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	// NOTE: Pro DB Hookup coming next!
	json.NewEncoder(w).Encode(map[string]any{"assignee": "IT Team", "token": token, "tickets": []any{}})
}

func (h *ProHandler) HandleMagicLinkSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PatchEvidence string `json:"patch_evidence"`
		Status        string `json:"status"`
		TicketIDs     []int  `json:"ticket_ids"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	log.Printf("🛠️ DEBUG: MagicLinkSubmit received %d tickets. Evidence: %s", len(req.TicketIDs), req.PatchEvidence)

	w.WriteHeader(http.StatusOK)
}

func (h *ProHandler) HandleSubmitRiskRequest(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Type      string `json:"type"`
		Rationale string `json:"rationale"`
	}
	json.NewDecoder(r.Body).Decode(&payload)

	w.WriteHeader(http.StatusOK)
}

func (h *ProHandler) HandleMagistrateReview(w http.ResponseWriter, r *http.Request) {
	var req MagistrateReviewRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Action == "Approve" && req.ExtensionDays <= 0 {
		req.ExtensionDays = 30
	}

	w.WriteHeader(http.StatusOK)
}

// Extract the ticket IDs from the JSON payload and pass them to the store
func (h *ProHandler) HandleWranglerReject(w http.ResponseWriter, r *http.Request) {
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
	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	if err := proStore.RejectTicketFromWrangler(r.Context(), req.TicketIDs, req.Reason, req.Comment); err != nil {
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
func (h *ProHandler) RejectTicketsHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Decode the JSON body
	var reqBody RejectRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Validate input
	if len(reqBody.TicketIDs) == 0 {
		http.Error(w, "At least one ticket ID is required", http.StatusBadRequest)
		return
	}
	if reqBody.Reason == "" {
		http.Error(w, "A rejection reason is required", http.StatusBadRequest)
		return
	}

	// 3. Cast the store to the Pro Interface
	proStore, ok := h.Store.(storage.ProStoreInterface)
	if !ok {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	// 4. Execute the rejection via the Pro database method
	err := proStore.RejectTicketFromWrangler(r.Context(), reqBody.TicketIDs, reqBody.Reason, reqBody.Comment)
	if err != nil {
		// In a real app, you might want to log this error
		http.Error(w, "Failed to reject tickets: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Return Success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Tickets successfully returned to the holding pen",
	})
}
