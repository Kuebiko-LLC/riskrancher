package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pro/evidence"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

const maxEvidenceBytes = 10 << 20 // 10 MB per upload

// ownsTicketOrSheriff reports whether the caller owns the engagement a finding
// belongs to (or is a Sheriff). Evidence attaches to engagement findings.
func (h *ProHandler) ownsTicketOrSheriff(r *http.Request, ticketID int) bool {
	u := h.currentUser(r)
	if u == nil {
		return false
	}
	if u.GlobalRole == "Sheriff" {
		return true
	}
	owner, err := h.ProStore.EngagementOwnerForTicket(r.Context(), ticketID)
	if err != nil {
		return false
	}
	return owner == u.Email
}

// HandleUploadEvidence accepts a multipart image upload (field "image" + optional
// "caption"), processes it (resize/thumbnail/strip metadata), and stores it on
// the finding. POST /api/findings/{id}/evidence
func (h *ProHandler) HandleUploadEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid finding id", http.StatusBadRequest)
		return
	}
	if !h.ownsTicketOrSheriff(r, tid) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEvidenceBytes)
	if err := r.ParseMultipartForm(maxEvidenceBytes); err != nil {
		http.Error(w, "Upload too large or malformed", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "An 'image' file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Could not read upload", http.StatusBadRequest)
		return
	}

	p, err := evidence.Process(raw)
	if err != nil {
		http.Error(w, "Not a valid PNG/JPEG/GIF image", http.StatusBadRequest)
		return
	}

	ev := &proModels.Evidence{
		TicketID:    tid,
		Caption:     r.FormValue("caption"),
		ContentType: p.ContentType,
		Width:       p.Width,
		Height:      p.Height,
		Size:        len(p.Web),
		CreatedBy:   h.currentUserEmail(r),
	}
	if _, err := h.ProStore.AddEvidence(r.Context(), ev, p.Web, p.Thumb); err != nil {
		httpServerError(w, "AddEvidence", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ev)
}

// HandleListEvidence lists a finding's evidence metadata.
// GET /api/findings/{id}/evidence
func (h *ProHandler) HandleListEvidence(w http.ResponseWriter, r *http.Request) {
	tid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid finding id", http.StatusBadRequest)
		return
	}
	if !h.ownsTicketOrSheriff(r, tid) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	list, err := h.ProStore.ListEvidenceForTicket(r.Context(), tid)
	if err != nil {
		httpServerError(w, "ListEvidence", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"evidence": list, "total": len(list)})
}

// HandleGetEvidenceImage serves the web image, or the thumbnail with ?thumb=1.
// GET /api/evidence/{id}
func (h *ProHandler) HandleGetEvidenceImage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid evidence id", http.StatusBadRequest)
		return
	}
	meta, err := h.ProStore.GetEvidenceMeta(r.Context(), id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if !h.ownsTicketOrSheriff(r, meta.TicketID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	data, ct, err := h.ProStore.GetEvidenceBlob(r.Context(), id, r.URL.Query().Get("thumb") == "1")
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=600")
	w.Write(data)
}

// HandleDeleteEvidence removes one evidence image. DELETE /api/evidence/{id}
func (h *ProHandler) HandleDeleteEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid evidence id", http.StatusBadRequest)
		return
	}
	meta, err := h.ProStore.GetEvidenceMeta(r.Context(), id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if !h.ownsTicketOrSheriff(r, meta.TicketID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := h.ProStore.DeleteEvidence(r.Context(), id); err != nil {
		httpServerError(w, "DeleteEvidence", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
