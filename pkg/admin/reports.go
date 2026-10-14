package admin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/reporting"
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

// renderReport fetches the findings the caller is allowed to see (released, own
// engagement, or any for a Sheriff) and renders the report to Markdown and HTML.
// Findings the caller may not see are dropped, so a report cannot exfiltrate
// another Bounty Hunter's held findings.
func (h *Handler) renderReport(r *http.Request, req generateReportRequest) ([]domain.Ticket, string, string) {
	email, sheriff := "", false
	if u := h.currentUser(r); u != nil {
		email, sheriff = u.Email, u.GlobalRole == "Sheriff"
	}
	tickets, _ := h.Store.FindingsVisibleTo(r.Context(), req.TicketIDs, email, sheriff)
	in := reporting.ReportInput{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
		Evidence:         h.evidenceForFindings(r, tickets),
	}
	return tickets, reporting.BuildMarkdown(in, tickets), reporting.BuildHTML(in, tickets)
}

// evidenceForFindings loads each finding's screenshots as base64 data URIs so
// the rendered report is self-contained.
func (h *Handler) evidenceForFindings(r *http.Request, tickets []domain.Ticket) map[int][]reporting.EvidenceImage {
	ev := map[int][]reporting.EvidenceImage{}
	for _, f := range tickets {
		list, err := h.Store.ListEvidenceForTicket(r.Context(), f.ID)
		if err != nil {
			continue
		}
		for _, m := range list {
			data, ct, err := h.Store.GetEvidenceBlob(r.Context(), m.ID, false)
			if err != nil {
				continue
			}
			uri := "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(data)
			ev[f.ID] = append(ev[f.ID], reporting.EvidenceImage{DataURI: uri, Caption: m.Caption})
		}
	}
	return ev
}

func ticketIDsOf(tickets []domain.Ticket) []int {
	ids := make([]int, len(tickets))
	for i, t := range tickets {
		ids[i] = t.ID
	}
	return ids
}

// canAccessReport reports whether the caller may read/edit a report (its author
// or a Sheriff).
func (h *Handler) canAccessReport(r *http.Request, rep *domain.PentestReport) bool {
	u := h.currentUser(r)
	if u == nil || rep == nil {
		return false
	}
	return u.GlobalRole == "Sheriff" || rep.CreatedBy == u.Email
}

// HandleGenerateBrandedReport turns a set of findings (tickets) into a pentest
// engagement report, renders it to Markdown and HTML, stores the frozen
// snapshot, and returns it. POST /api/reports/branded
func (h *Handler) HandleGenerateBrandedReport(w http.ResponseWriter, r *http.Request) {
	var req generateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if len(req.TicketIDs) == 0 {
		http.Error(w, "ticket_ids is required (select at least one finding)", http.StatusBadRequest)
		return
	}
	if len(req.TicketIDs) > maxFindingsPerRequest {
		http.Error(w, "too many ticket_ids", http.StatusBadRequest)
		return
	}

	findings, md, html := h.renderReport(r, req)
	if len(findings) == 0 {
		http.Error(w, "none of the requested findings are visible to you", http.StatusNotFound)
		return
	}

	report := &domain.PentestReport{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
		EngagementID:     req.EngagementID,
		TicketIDs:        ticketIDsOf(findings),
		Markdown:         md,
		HTML:             html,
		CreatedBy:        h.currentUserEmail(r),
	}

	if _, err := h.Store.CreatePentestReport(r.Context(), report); err != nil {
		httpServerError(w, "db", err)
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
func (h *Handler) HandleUpdateReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid report id", http.StatusBadRequest)
		return
	}
	existing, err := h.Store.GetPentestReport(r.Context(), id)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if !h.canAccessReport(r, existing) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req generateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if len(req.TicketIDs) > maxFindingsPerRequest {
		http.Error(w, "too many ticket_ids", http.StatusBadRequest)
		return
	}

	findings, md, html := h.renderReport(r, req)

	updated := &domain.PentestReport{
		ID:               id,
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		Body:             req.Body,
		EngagementID:     req.EngagementID,
		TicketIDs:        ticketIDsOf(findings),
		Markdown:         md,
		HTML:             html,
		CreatedBy:        existing.CreatedBy,
		CreatedAt:        existing.CreatedAt,
	}
	if err := h.Store.UpdateReport(r.Context(), updated); err != nil {
		httpServerError(w, "db", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// HandleGetPentestReport returns one stored report. The ?format query selects
// the representation: json (default), md, or html (served as a downloadable
// document). GET /api/reports/branded/{id}
func (h *Handler) HandleGetPentestReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid report id", http.StatusBadRequest)
		return
	}

	report, err := h.Store.GetPentestReport(r.Context(), id)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	if !h.canAccessReport(r, report) {
		http.Error(w, "Forbidden", http.StatusForbidden)
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
func (h *Handler) HandleListPentestReports(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var (
		reports []domain.PentestReport
		err     error
	)
	if u.GlobalRole == "Sheriff" {
		reports, err = h.Store.ListPentestReports(r.Context())
	} else {
		reports, err = h.Store.ListPentestReportsByAuthor(r.Context(), u.Email)
	}
	if err != nil {
		httpServerError(w, "db", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"reports": reports, "total": len(reports)})
}

// currentUser resolves the signed-in user, or nil if none is present.
func (h *Handler) currentUser(r *http.Request) *domain.User {
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
func (h *Handler) currentUserEmail(r *http.Request) string {
	if u := h.currentUser(r); u != nil {
		return u.Email
	}
	return ""
}

// isOwnerOrSheriff reports whether the caller owns the engagement or is a Sheriff.
func (h *Handler) isOwnerOrSheriff(r *http.Request, eng *domain.Engagement) bool {
	u := h.currentUser(r)
	if u == nil || eng == nil {
		return false
	}
	return u.GlobalRole == "Sheriff" || eng.OwnerEmail == u.Email
}
