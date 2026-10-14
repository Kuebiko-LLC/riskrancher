package tickets

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type InlineUpdateRequest struct {
	Severity               string `json:"severity"`
	Comment                string `json:"comment"`
	Description            string `json:"description"`
	RecommendedRemediation string `json:"recommended_remediation"`
	Actor                  string `json:"actor"`
	Status                 string `json:"status"`
	Assignee               string `json:"assignee"`
}

type BulkUpdateRequest struct {
	TicketIDs []int  `json:"ticket_ids"`
	Status    string `json:"status"`
	Comment   string `json:"comment"`
	Assignee  string `json:"assignee"`
	Actor     string `json:"actor"`
}

type MagistrateReviewRequest struct {
	Action        string `json:"action"`
	Actor         string `json:"actor"`
	Comment       string `json:"comment"`
	ExtensionDays int    `json:"extension_days"`
	TicketIDs     []int  `json:"ticket_ids"`
}

// actor names the signed-in user for the audit trail. A body may carry an
// actor field for callers without a session (tests, scripts); a session wins.
func (h *Handler) actor(r *http.Request, fromBody string) string {
	if uid, ok := r.Context().Value(auth.UserIDKey).(int); ok {
		if u, err := h.Store.GetUserByID(r.Context(), uid); err == nil && u.Email != "" {
			return u.Email
		}
	}
	if fromBody == "" {
		return "Unknown"
	}
	return fromBody
}

func (h *Handler) HandleUpdateTicket(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var req InlineUpdateRequest
	json.NewDecoder(r.Body).Decode(&req)

	if err := h.Store.UpdateTicketInline(r.Context(), id, req.Severity, req.Description, req.RecommendedRemediation, req.Comment, h.actor(r, req.Actor), req.Status, req.Assignee); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleTicketActivity is a finding's history for the drawer.
func (h *Handler) HandleTicketActivity(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	entries, err := h.Store.TicketActivity(r.Context(), id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// HandleGetTickets fetches a list of tickets via the API
func (h *Handler) HandleGetTickets(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	tickets, err := h.Store.GetTickets(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tickets)
}

// HandleCreateTicket creates a single ticket via the API
func (h *Handler) HandleCreateTicket(w http.ResponseWriter, r *http.Request) {
	var t domain.Ticket
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if err := h.Store.CreateTicket(r.Context(), &t); err != nil {
		http.Error(w, "Failed to create ticket", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}
