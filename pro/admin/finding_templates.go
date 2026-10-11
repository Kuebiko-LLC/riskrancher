package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

type templateRequest struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Tags        string `json:"tags"`
}

// HandleListTemplates returns the shared finding-template library.
// GET /api/finding-templates
func (h *ProHandler) HandleListTemplates(w http.ResponseWriter, r *http.Request) {
	list, err := h.ProStore.ListFindingTemplates(r.Context())
	if err != nil {
		httpServerError(w, "ListFindingTemplates", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"templates": list, "total": len(list)})
}

// HandleGetTemplate returns one template. GET /api/finding-templates/{id}
func (h *ProHandler) HandleGetTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid template id", http.StatusBadRequest)
		return
	}
	tpl, err := h.ProStore.GetFindingTemplate(r.Context(), id)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tpl)
}

// HandleCreateTemplate adds a template to the library. POST /api/finding-templates
func (h *ProHandler) HandleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req templateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		http.Error(w, "invalid severity", http.StatusBadRequest)
		return
	}
	tpl := &proModels.FindingTemplate{
		Name: req.Name, Title: req.Title, Severity: req.Severity,
		Description: req.Description, Remediation: req.Remediation, Tags: req.Tags,
		CreatedBy: h.currentUserEmail(r),
	}
	if _, err := h.ProStore.CreateFindingTemplate(r.Context(), tpl); err != nil {
		httpServerError(w, "CreateFindingTemplate", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tpl)
}

// HandleUpdateTemplate edits a template. PUT /api/finding-templates/{id}
func (h *ProHandler) HandleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid template id", http.StatusBadRequest)
		return
	}
	var req templateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		http.Error(w, "invalid severity", http.StatusBadRequest)
		return
	}
	tpl := &proModels.FindingTemplate{
		ID: id, Name: req.Name, Title: req.Title, Severity: req.Severity,
		Description: req.Description, Remediation: req.Remediation, Tags: req.Tags,
	}
	if err := h.ProStore.UpdateFindingTemplate(r.Context(), tpl); err != nil {
		httpServerError(w, "UpdateFindingTemplate", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tpl)
}

// HandleDeleteTemplate removes a template. DELETE /api/finding-templates/{id}
func (h *ProHandler) HandleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid template id", http.StatusBadRequest)
		return
	}
	if err := h.ProStore.DeleteFindingTemplate(r.Context(), id); err != nil {
		httpServerError(w, "DeleteFindingTemplate", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// HandleApplyTemplate instantiates a template as a new finding on an engagement
// (owner-only). POST /api/engagements/{id}/apply-template  {template_id, asset}
func (h *ProHandler) HandleApplyTemplate(w http.ResponseWriter, r *http.Request) {
	engID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid engagement id", http.StatusBadRequest)
		return
	}
	eng, err := h.ProStore.GetEngagement(r.Context(), engID)
	if err != nil {
		http.Error(w, "Engagement not found", http.StatusNotFound)
		return
	}
	if !h.isOwnerOrSheriff(r, eng) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		TemplateID int    `json:"template_id"`
		Asset      string `json:"asset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.TemplateID == 0 || req.Asset == "" {
		http.Error(w, "template_id and asset are required", http.StatusBadRequest)
		return
	}
	fid, err := h.ProStore.CreateFindingFromTemplate(r.Context(), req.TemplateID, engID, req.Asset, h.currentUserEmail(r))
	if err != nil {
		httpServerError(w, "CreateFindingFromTemplate", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]int{"finding_id": fid})
}
