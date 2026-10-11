package storage

import (
	"context"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

const findingTemplateCols = `id, name, title, severity, description, remediation, tags, created_by, created_at, updated_at`

func scanFindingTemplate(row interface{ Scan(...any) error }) (*proModels.FindingTemplate, error) {
	var t proModels.FindingTemplate
	if err := row.Scan(&t.ID, &t.Name, &t.Title, &t.Severity, &t.Description, &t.Remediation, &t.Tags, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateFindingTemplate inserts a new template and sets its id on the struct.
func (s *ProSQLiteStore) CreateFindingTemplate(ctx context.Context, t *proModels.FindingTemplate) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_templates (name, title, severity, description, remediation, tags, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.Name, t.Title, t.Severity, t.Description, t.Remediation, t.Tags, t.CreatedBy)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	t.ID = int(id)
	_ = s.db.QueryRowContext(ctx, `SELECT created_at, updated_at FROM finding_templates WHERE id = ?`, t.ID).Scan(&t.CreatedAt, &t.UpdatedAt)
	return t.ID, nil
}

func (s *ProSQLiteStore) GetFindingTemplate(ctx context.Context, id int) (*proModels.FindingTemplate, error) {
	return scanFindingTemplate(s.db.QueryRowContext(ctx, `SELECT `+findingTemplateCols+` FROM finding_templates WHERE id = ?`, id))
}

func (s *ProSQLiteStore) ListFindingTemplates(ctx context.Context) ([]proModels.FindingTemplate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingTemplateCols+` FROM finding_templates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proModels.FindingTemplate
	for rows.Next() {
		t, err := scanFindingTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *ProSQLiteStore) UpdateFindingTemplate(ctx context.Context, t *proModels.FindingTemplate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE finding_templates SET name = ?, title = ?, severity = ?, description = ?, remediation = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		t.Name, t.Title, t.Severity, t.Description, t.Remediation, t.Tags, t.ID)
	return err
}

func (s *ProSQLiteStore) DeleteFindingTemplate(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM finding_templates WHERE id = ?`, id)
	return err
}

// CreateFindingFromTemplate instantiates a template as a new finding on an
// engagement (held out of the triage queue until release), prefilled from the
// template and targeted at the given asset. Returns the new finding id.
func (s *ProSQLiteStore) CreateFindingFromTemplate(ctx context.Context, templateID, engagementID int, asset, actor string) (int, error) {
	tpl, err := s.GetFindingTemplate(ctx, templateID)
	if err != nil {
		return 0, err
	}
	tk := &coredomain.Ticket{
		Source:                 "Template",
		AssetIdentifier:        asset,
		Title:                  tpl.Title,
		Description:            tpl.Description,
		RecommendedRemediation: tpl.Remediation,
		Severity:               tpl.Severity,
		Status:                 "Waiting to be Triaged",
	}
	if err := s.CreateTicket(ctx, tk); err != nil {
		return 0, err
	}
	if err := s.AddFindingsToEngagement(ctx, engagementID, []int{tk.ID}); err != nil {
		return 0, err
	}
	return tk.ID, nil
}
