package storage

import (
	"context"
	"database/sql"
	"encoding/json"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

func marshalIDs(ids []int) string {
	if ids == nil {
		ids = []int{}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

// CreatePentestReport persists a report (its editable fields plus the rendered
// Markdown and HTML) and returns its new id.
func (s *ProSQLiteStore) CreatePentestReport(ctx context.Context, report *proModels.PentestReport) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO pentest_reports
			(title, client_name, author, scope, executive_summary, body, engagement_id, ticket_ids, markdown, html, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.Title, report.ClientName, report.Author, report.Scope, report.ExecutiveSummary,
		report.Body, report.EngagementID, marshalIDs(report.TicketIDs), report.Markdown, report.HTML, report.CreatedBy,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	report.ID = int(id)
	return report.ID, nil
}

// UpdateReport persists edits to a report, including the re-rendered Markdown
// and HTML. The report keeps its id, created_by, and created_at.
func (s *ProSQLiteStore) UpdateReport(ctx context.Context, report *proModels.PentestReport) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE pentest_reports SET
			title = ?, client_name = ?, author = ?, scope = ?, executive_summary = ?,
			body = ?, engagement_id = ?, ticket_ids = ?, markdown = ?, html = ?
		WHERE id = ?`,
		report.Title, report.ClientName, report.Author, report.Scope, report.ExecutiveSummary,
		report.Body, report.EngagementID, marshalIDs(report.TicketIDs), report.Markdown, report.HTML, report.ID,
	)
	return err
}

// GetPentestReport returns one stored report, including the rendered bodies.
func (s *ProSQLiteStore) GetPentestReport(ctx context.Context, id int) (*proModels.PentestReport, error) {
	var r proModels.PentestReport
	var idsJSON string
	var body sql.NullString
	var engagementID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, client_name, author, scope, executive_summary, body, engagement_id, ticket_ids, markdown, html, created_by, created_at
		FROM pentest_reports WHERE id = ?`, id,
	).Scan(&r.ID, &r.Title, &r.ClientName, &r.Author, &r.Scope, &r.ExecutiveSummary,
		&body, &engagementID, &idsJSON, &r.Markdown, &r.HTML, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.Body = body.String
	r.EngagementID = int(engagementID.Int64)
	_ = json.Unmarshal([]byte(idsJSON), &r.TicketIDs)
	return &r, nil
}

// ListPentestReports returns report metadata newest-first. The heavy rendered
// bodies are omitted from the list view.
func (s *ProSQLiteStore) ListPentestReports(ctx context.Context) ([]proModels.PentestReport, error) {
	return s.listReports(ctx, "", nil)
}

// ListPentestReportsByAuthor returns only the reports created by author.
func (s *ProSQLiteStore) ListPentestReportsByAuthor(ctx context.Context, author string) ([]proModels.PentestReport, error) {
	return s.listReports(ctx, "WHERE created_by = ?", []any{author})
}

func (s *ProSQLiteStore) listReports(ctx context.Context, where string, args []any) ([]proModels.PentestReport, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, client_name, author, scope, executive_summary, ticket_ids, created_by, created_at
		FROM pentest_reports `+where+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []proModels.PentestReport
	for rows.Next() {
		var r proModels.PentestReport
		var idsJSON string
		if err := rows.Scan(&r.ID, &r.Title, &r.ClientName, &r.Author, &r.Scope,
			&r.ExecutiveSummary, &idsJSON, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &r.TicketIDs)
		reports = append(reports, r)
	}
	return reports, rows.Err()
}
