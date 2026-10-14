package admin

import (
	"encoding/json"
	"errors"
	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"net/http"
	"strconv"
)

// HandleProposeSeverity lets a RangeHand propose a severity change on a
// Bounty-Hunter-origin finding (it does not apply it).
// POST /api/findings/{id}/severity-proposal  { "to_severity": ..., "justification": ... }
func (h *Handler) HandleProposeSeverity(w http.ResponseWriter, r *http.Request) {
	ticketID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid finding id", http.StatusBadRequest)
		return
	}
	var req struct {
		ToSeverity    string `json:"to_severity"`
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Justification == "" {
		http.Error(w, "justification is required", http.StatusBadRequest)
		return
	}
	if !validSeverity(req.ToSeverity) {
		http.Error(w, "to_severity must be one of Critical, High, Medium, Low, Informational", http.StatusBadRequest)
		return
	}

	p, err := h.Store.ProposeSeverityChange(r.Context(), ticketID, req.ToSeverity, req.Justification, h.currentUserEmail(r))
	if err != nil {
		switch {
		case errors.Is(err, datastore.ErrNotBountyHunterFinding):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, datastore.ErrProposalAlreadyOpen):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			httpServerError(w, "ProposeSeverityChange", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

// ownsProposalOrSheriff reports whether the caller owns the engagement behind a
// proposal (or is a Sheriff), for owner-only accept/contest.
func (h *Handler) ownsProposalOrSheriff(r *http.Request, proposalID int) bool {
	u := h.currentUser(r)
	if u == nil {
		return false
	}
	if u.GlobalRole == "Sheriff" {
		return true
	}
	owner, err := h.Store.EngagementOwnerForProposal(r.Context(), proposalID)
	if err != nil {
		return false
	}
	return owner == u.Email
}

// proposalStateError maps a state-machine rejection to 409, else 500.
func proposalStateError(w http.ResponseWriter, err error) {
	if errors.Is(err, datastore.ErrProposalNotPending) || errors.Is(err, datastore.ErrProposalNotContested) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Error(w, "Could not update proposal", http.StatusInternalServerError)
}

// HandleAcceptSeverityProposal (owning Bounty Hunter) applies a proposed severity.
// POST /api/severity-proposals/{id}/accept
func (h *Handler) HandleAcceptSeverityProposal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid proposal id", http.StatusBadRequest)
		return
	}
	if !h.ownsProposalOrSheriff(r, id) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := h.Store.AcceptSeverityProposal(r.Context(), id, h.currentUserEmail(r)); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// HandleContestSeverityProposal (Bounty Hunter) escalates a proposal to the Sheriff.
// POST /api/severity-proposals/{id}/contest  { "note": ... }
func (h *Handler) HandleContestSeverityProposal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid proposal id", http.StatusBadRequest)
		return
	}
	if !h.ownsProposalOrSheriff(r, id) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := h.Store.ContestSeverityProposal(r.Context(), id, h.currentUserEmail(r), req.Note); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "contested"})
}

// HandleAdjudicateSeverityProposal (Sheriff) breaks the tie and applies the final call.
// POST /api/severity-proposals/{id}/adjudicate  { "final_severity": ..., "note": ... }
func (h *Handler) HandleAdjudicateSeverityProposal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid proposal id", http.StatusBadRequest)
		return
	}
	var req struct {
		FinalSeverity string `json:"final_severity"`
		Note          string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if !validSeverity(req.FinalSeverity) {
		http.Error(w, "final_severity must be one of Critical, High, Medium, Low, Informational", http.StatusBadRequest)
		return
	}
	if err := h.Store.AdjudicateSeverityProposal(r.Context(), id, req.FinalSeverity, h.currentUserEmail(r), req.Note); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "resolved"})
}

// HandleMyPendingProposals (Bounty Hunter) is the alert feed of pending
// proposals on the caller's own engagements.
// GET /api/severity-proposals/mine
func (h *Handler) HandleMyPendingProposals(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.ListPendingProposalsForOwner(r.Context(), h.currentUserEmail(r))
	if err != nil {
		httpServerError(w, "db", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"proposals": list, "total": len(list)})
}

// HandleContestedProposals (Sheriff) is the adjudication queue.
// GET /api/severity-proposals/contested
func (h *Handler) HandleContestedProposals(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.ListContestedProposals(r.Context())
	if err != nil {
		httpServerError(w, "db", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"proposals": list, "total": len(list)})
}
