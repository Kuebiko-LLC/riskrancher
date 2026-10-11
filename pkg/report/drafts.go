package report

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (h *Handler) HandleSaveDraft(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("id")

	var draft domain2.DraftTicket
	if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	draft.ReportID = reportID

	if err := h.Store.SaveDraft(r.Context(), draft); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) HandleGetDrafts(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("id")

	drafts, err := h.Store.GetDraftsByReport(r.Context(), reportID)
	if err != nil {
		http.Error(w, "Failed to get drafts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drafts)
}

func (h *Handler) HandleDeleteDraft(w http.ResponseWriter, r *http.Request) {
	draftID := r.PathValue("draft_id")

	if err := h.Store.DeleteDraft(r.Context(), draftID); err != nil {
		http.Error(w, "Failed to delete draft", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HandlePromoteDrafts(w http.ResponseWriter, r *http.Request) {
	reportIDStr := r.PathValue("id")
	if reportIDStr == "" {
		http.Error(w, "Invalid Report ID", http.StatusBadRequest)
		return
	}

	userIDVal := r.Context().Value(auth.UserIDKey)
	if userIDVal == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.Store.GetUserByID(r.Context(), userIDVal.(int))
	if err != nil {
		http.Error(w, "Failed to identify user", http.StatusInternalServerError)
		return
	}
	analystEmail := user.Email

	var payload []domain2.Ticket
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	if err := h.Store.PromotePentestDrafts(r.Context(), reportIDStr, analystEmail, payload); err != nil {
		http.Error(w, "Database error during promotion: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) HandleUpdateDraft(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	draftID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid draft ID", http.StatusBadRequest)
		return
	}

	var payload domain2.Ticket
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.Store.UpdateDraft(r.Context(), draftID, payload); err != nil {
		http.Error(w, "Failed to auto-save draft", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
