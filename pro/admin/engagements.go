package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// HandleCreateEngagement lets a Bounty Hunter open a new engagement they own.
// POST /api/engagements  { "name": ..., "client": ... }
func (h *ProHandler) HandleCreateEngagement(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Client string `json:"client"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	e := &proModels.Engagement{Name: req.Name, Client: req.Client, OwnerEmail: h.currentUserEmail(r)}
	if _, err := h.ProStore.CreateEngagement(r.Context(), e); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(e)
}

// HandleListEngagements returns engagements the caller may see: a Bounty Hunter
// sees their own, a Sheriff sees all. GET /api/engagements
func (h *ProHandler) HandleListEngagements(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var (
		list []proModels.Engagement
		err  error
	)
	if u.GlobalRole == "Sheriff" {
		list, err = h.ProStore.ListEngagements(r.Context())
	} else {
		list, err = h.ProStore.ListEngagementsByOwner(r.Context(), u.Email)
	}
	if err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"engagements": list, "total": len(list)})
}

// HandleGetEngagement returns one engagement and its findings. Restricted to the
// owning Bounty Hunter or a Sheriff so unreleased findings do not leak.
// GET /api/engagements/{id}
func (h *ProHandler) HandleGetEngagement(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid engagement id", http.StatusBadRequest)
		return
	}
	eng, err := h.ProStore.GetEngagement(r.Context(), id)
	if err != nil {
		http.Error(w, "Engagement not found", http.StatusNotFound)
		return
	}
	if !h.isOwnerOrSheriff(r, eng) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	findings, err := h.ProStore.ListEngagementFindings(r.Context(), id)
	if err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"engagement": eng, "findings": findings})
}

// HandleAddEngagementFindings links findings to an engagement.
// POST /api/engagements/{id}/findings  { "ticket_ids": [...] }
func (h *ProHandler) HandleAddEngagementFindings(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid engagement id", http.StatusBadRequest)
		return
	}
	eng, err := h.ProStore.GetEngagement(r.Context(), id)
	if err != nil {
		http.Error(w, "Engagement not found", http.StatusNotFound)
		return
	}
	if !h.isOwnerOrSheriff(r, eng) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		TicketIDs []int `json:"ticket_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := h.ProStore.AddFindingsToEngagement(r.Context(), id, req.TicketIDs); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"added": len(req.TicketIDs)})
}

// HandleReleaseEngagement hands an engagement's findings off to the RangeHand
// queue. POST /api/engagements/{id}/release
func (h *ProHandler) HandleReleaseEngagement(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid engagement id", http.StatusBadRequest)
		return
	}
	eng, err := h.ProStore.GetEngagement(r.Context(), id)
	if err != nil {
		http.Error(w, "Engagement not found", http.StatusNotFound)
		return
	}
	if !h.isOwnerOrSheriff(r, eng) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := h.ProStore.ReleaseEngagement(r.Context(), id); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	eng, _ = h.ProStore.GetEngagement(r.Context(), id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(eng)
}
