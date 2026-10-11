package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// HandleProposeSeverity lets a RangeHand propose a severity change on a
// Bounty-Hunter-origin finding (it does not apply it).
// POST /api/findings/{id}/severity-proposal  { "to_severity": ..., "justification": ... }
func (h *ProHandler) HandleProposeSeverity(w http.ResponseWriter, r *http.Request) {
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
	if req.ToSeverity == "" || req.Justification == "" {
		http.Error(w, "to_severity and justification are required", http.StatusBadRequest)
		return
	}

	p, err := h.ProStore.ProposeSeverityChange(r.Context(), ticketID, req.ToSeverity, req.Justification, h.currentUserEmail(r))
	if err != nil {
		if errors.Is(err, storage.ErrNotBountyHunterFinding) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

// ownsProposalOrSheriff reports whether the caller owns the engagement behind a
// proposal (or is a Sheriff), for owner-only accept/contest.
func (h *ProHandler) ownsProposalOrSheriff(r *http.Request, proposalID int) bool {
	u := h.currentUser(r)
	if u == nil {
		return false
	}
	if u.GlobalRole == "Sheriff" {
		return true
	}
	owner, err := h.ProStore.EngagementOwnerForProposal(r.Context(), proposalID)
	if err != nil {
		return false
	}
	return owner == u.Email
}

// proposalStateError maps a state-machine rejection to 409, else 500.
func proposalStateError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrProposalNotPending) || errors.Is(err, storage.ErrProposalNotContested) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Error(w, "Could not update proposal", http.StatusInternalServerError)
}

// HandleAcceptSeverityProposal (owning Bounty Hunter) applies a proposed severity.
// POST /api/severity-proposals/{id}/accept
func (h *ProHandler) HandleAcceptSeverityProposal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid proposal id", http.StatusBadRequest)
		return
	}
	if !h.ownsProposalOrSheriff(r, id) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := h.ProStore.AcceptSeverityProposal(r.Context(), id, h.currentUserEmail(r)); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// HandleContestSeverityProposal (Bounty Hunter) escalates a proposal to the Sheriff.
// POST /api/severity-proposals/{id}/contest  { "note": ... }
func (h *ProHandler) HandleContestSeverityProposal(w http.ResponseWriter, r *http.Request) {
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
	if err := h.ProStore.ContestSeverityProposal(r.Context(), id, h.currentUserEmail(r), req.Note); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "contested"})
}

// HandleAdjudicateSeverityProposal (Sheriff) breaks the tie and applies the final call.
// POST /api/severity-proposals/{id}/adjudicate  { "final_severity": ..., "note": ... }
func (h *ProHandler) HandleAdjudicateSeverityProposal(w http.ResponseWriter, r *http.Request) {
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
	if req.FinalSeverity == "" {
		http.Error(w, "final_severity is required", http.StatusBadRequest)
		return
	}
	if err := h.ProStore.AdjudicateSeverityProposal(r.Context(), id, req.FinalSeverity, h.currentUserEmail(r), req.Note); err != nil {
		proposalStateError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "resolved"})
}

// HandleMyPendingProposals (Bounty Hunter) is the alert feed of pending
// proposals on the caller's own engagements.
// GET /api/severity-proposals/mine
func (h *ProHandler) HandleMyPendingProposals(w http.ResponseWriter, r *http.Request) {
	list, err := h.ProStore.ListPendingProposalsForOwner(r.Context(), h.currentUserEmail(r))
	if err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"proposals": list, "total": len(list)})
}

// HandleContestedProposals (Sheriff) is the adjudication queue.
// GET /api/severity-proposals/contested
func (h *ProHandler) HandleContestedProposals(w http.ResponseWriter, r *http.Request) {
	list, err := h.ProStore.ListContestedProposals(r.Context())
	if err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"proposals": list, "total": len(list)})
}
