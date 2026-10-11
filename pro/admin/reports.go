package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/reporting"
)

type generateReportRequest struct {
	Title            string `json:"title"`
	ClientName       string `json:"client_name"`
	Author           string `json:"author"`
	Scope            string `json:"scope"`
	ExecutiveSummary string `json:"executive_summary"`
	Body             string `json:"body"`
	EngagementID     int    `json:"engagement_id"`
	TicketIDs        []int  `json:"ticket_ids"`
}

// renderReport fetches the selected findings and renders the report to Markdown
// and HTML. Missing ticket ids are skipped so a stale selection still renders.
func (h *ProHandler) renderReport(r *http.Request, req generateReportRequest) (findings int, md, html string) {
	var tickets []coredomain.Ticket
	for _, id := range req.TicketIDs {
		t, err := h.Store.GetTicketByID(r.Context(), id)
		if err != nil {
			continue
		}
		tickets = append(tickets, t)
	}
	in := reporting.ReportInput{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
	}
	return len(tickets), reporting.BuildMarkdown(in, tickets), reporting.BuildHTML(in, tickets)
}

// HandleGenerateBrandedReport turns a set of findings (tickets) into a pentest
// engagement report, renders it to Markdown and HTML, stores the frozen
// snapshot, and returns it. POST /api/reports/branded
func (h *ProHandler) HandleGenerateBrandedReport(w http.ResponseWriter, r *http.Request) {
	var req generateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if len(req.TicketIDs) == 0 {
		http.Error(w, "ticket_ids is required (select at least one finding)", http.StatusBadRequest)
		return
	}

	matched, md, html := h.renderReport(r, req)
	if matched == 0 {
		http.Error(w, "none of the requested ticket_ids matched a finding", http.StatusNotFound)
		return
	}

	report := &proModels.PentestReport{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
		EngagementID:     req.EngagementID,
		TicketIDs:        req.TicketIDs,
		Markdown:         md,
		HTML:             html,
		CreatedBy:        h.currentUserEmail(r),
	}

	if _, err := h.ProStore.CreatePentestReport(r.Context(), report); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(report)
}

// HandleUpdateReport saves edits to a report (prose and finding selection),
// re-renders the Markdown and HTML, and returns the updated report. The report
// is a live document, so edits are persisted and shown on the next read.
// PUT /api/reports/branded/{id}
func (h *ProHandler) HandleUpdateReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid report id", http.StatusBadRequest)
		return
	}
	existing, err := h.ProStore.GetPentestReport(r.Context(), id)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	var req generateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, md, html := h.renderReport(r, req)

	updated := &proModels.PentestReport{
		ID:               id,
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
		EngagementID:     req.EngagementID,
		TicketIDs:        req.TicketIDs,
		Markdown:         md,
		HTML:             html,
		CreatedBy:        existing.CreatedBy,
		CreatedAt:        existing.CreatedAt,
	}
	if err := h.ProStore.UpdateReport(r.Context(), updated); err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// HandleGetPentestReport returns one stored report. The ?format query selects
// the representation: json (default), md, or html (served as a downloadable
// document). GET /api/reports/branded/{id}
func (h *ProHandler) HandleGetPentestReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid report id", http.StatusBadRequest)
		return
	}

	report, err := h.ProStore.GetPentestReport(r.Context(), id)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	switch r.URL.Query().Get("format") {
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"report-"+strconv.Itoa(id)+".md\"")
		w.Write([]byte(report.Markdown))
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(report.HTML))
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)
	}
}

// HandleListPentestReports returns report metadata (no rendered bodies).
// GET /api/reports/generated
func (h *ProHandler) HandleListPentestReports(w http.ResponseWriter, r *http.Request) {
	reports, err := h.ProStore.ListPentestReports(r.Context())
	if err != nil {
		http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"reports": reports, "total": len(reports)})
}

// currentUser resolves the signed-in user, or nil if none is present.
func (h *ProHandler) currentUser(r *http.Request) *coredomain.User {
	id, ok := r.Context().Value(auth.UserIDKey).(int)
	if !ok {
		return nil
	}
	u, err := h.Store.GetUserByID(r.Context(), id)
	if err != nil {
		return nil
	}
	return u
}

// currentUserEmail best-effort resolves the signed-in user's email. Returns ""
// when no authenticated user is present.
func (h *ProHandler) currentUserEmail(r *http.Request) string {
	if u := h.currentUser(r); u != nil {
		return u.Email
	}
	return ""
}

// isOwnerOrSheriff reports whether the caller owns the engagement or is a Sheriff.
func (h *ProHandler) isOwnerOrSheriff(r *http.Request, eng *proModels.Engagement) bool {
	u := h.currentUser(r)
	if u == nil || eng == nil {
		return false
	}
	return u.GlobalRole == "Sheriff" || eng.OwnerEmail == u.Email
}
