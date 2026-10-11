package storage

import (
	"context"
	"encoding/json"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// CreatePentestReport persists a generated engagement report (a frozen snapshot
// of the selected findings plus the rendered Markdown and HTML) and returns its
// new id.
func (s *ProSQLiteStore) CreatePentestReport(ctx context.Context, report *proModels.PentestReport) (int, error) {
	ids := report.TicketIDs
	if ids == nil {
		ids = []int{}
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return 0, err
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO pentest_reports
			(title, client_name, author, scope, executive_summary, ticket_ids, markdown, html, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.Title, report.ClientName, report.Author, report.Scope, report.ExecutiveSummary,
		string(idsJSON), report.Markdown, report.HTML, report.CreatedBy,
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

// GetPentestReport returns one stored report, including the rendered bodies.
func (s *ProSQLiteStore) GetPentestReport(ctx context.Context, id int) (*proModels.PentestReport, error) {
	var r proModels.PentestReport
	var idsJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, client_name, author, scope, executive_summary, ticket_ids, markdown, html, created_by, created_at
		FROM pentest_reports WHERE id = ?`, id,
	).Scan(&r.ID, &r.Title, &r.ClientName, &r.Author, &r.Scope, &r.ExecutiveSummary,
		&idsJSON, &r.Markdown, &r.HTML, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(idsJSON), &r.TicketIDs)
	return &r, nil
}

// ListPentestReports returns report metadata newest-first. The heavy rendered
// bodies are omitted from the list view.
func (s *ProSQLiteStore) ListPentestReports(ctx context.Context) ([]proModels.PentestReport, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, client_name, author, scope, executive_summary, ticket_ids, created_by, created_at
		FROM pentest_reports ORDER BY created_at DESC, id DESC`)
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
