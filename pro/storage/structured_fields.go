package storage

import (
	"context"
	"database/sql"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// scanReportTicket scans the report-grade finding columns (incl. the structured
// fields, which are nullable for non-report findings) into a Ticket. The SELECT
// must list: id, source, asset_identifier, title, description,
// recommended_remediation, severity, status, cvss_vector, cvss_score, cwe,
// business_impact (in that order).
func scanReportTicket(row interface{ Scan(...any) error }) (coredomain.Ticket, error) {
	var t coredomain.Ticket
	var cvssVec, cwe, bi sql.NullString
	var cvssScore sql.NullFloat64
	if err := row.Scan(&t.ID, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation,
		&t.Severity, &t.Status, &cvssVec, &cvssScore, &cwe, &bi); err != nil {
		return t, err
	}
	t.CVSSVector = cvssVec.String
	t.CVSSScore = cvssScore.Float64
	t.CWE = cwe.String
	t.BusinessImpact = bi.String
	return t, nil
}

// FindingDetails are the editable, report-grade fields of a finding.
type FindingDetails struct {
	Severity       string
	Description    string
	Remediation    string
	CVSSVector     string
	CVSSScore      float64
	CWE            string
	BusinessImpact string
}

// UpdateFindingDetails writes the structured report fields of a finding.
func (s *ProSQLiteStore) UpdateFindingDetails(ctx context.Context, ticketID int, d FindingDetails) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE tickets SET
			severity = ?, description = ?, recommended_remediation = ?,
			cvss_vector = ?, cvss_score = ?, cwe = ?, business_impact = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		d.Severity, d.Description, d.Remediation, d.CVSSVector, d.CVSSScore, d.CWE, d.BusinessImpact, ticketID)
	return err
}
