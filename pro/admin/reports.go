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
	TicketIDs        []int  `json:"ticket_ids"`
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

	// Pull the selected findings. Missing IDs are skipped rather than failing
	// the whole report, so a stale selection still produces a deliverable.
	findings := make([]coredomain.Ticket, 0, len(req.TicketIDs))
	for _, id := range req.TicketIDs {
		t, err := h.Store.GetTicketByID(r.Context(), id)
		if err != nil {
			continue
		}
		findings = append(findings, t)
	}
	if len(findings) == 0 {
		http.Error(w, "none of the requested ticket_ids matched a finding", http.StatusNotFound)
		return
	}

	in := reporting.ReportInput{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
	}

	report := &proModels.PentestReport{
		Title:            req.Title,
		ClientName:       req.ClientName,
		Author:           req.Author,
		Scope:            req.Scope,
		ExecutiveSummary: req.ExecutiveSummary,
		TicketIDs:        req.TicketIDs,
		Markdown:         reporting.BuildMarkdown(in, findings),
		HTML:             reporting.BuildHTML(in, findings),
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

// currentUserEmail best-effort resolves the signed-in user's email for the
// report's created_by field. Returns "" when no authenticated user is present.
func (h *ProHandler) currentUserEmail(r *http.Request) string {
	id, ok := r.Context().Value(auth.UserIDKey).(int)
	if !ok {
		return ""
	}
	u, err := h.Store.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		return ""
	}
	return u.Email
}
