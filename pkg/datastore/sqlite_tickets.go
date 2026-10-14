package datastore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (s *SQLiteStore) GetTickets(ctx context.Context) ([]domain.Ticket, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, title, severity, status FROM tickets LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tickets []domain.Ticket
	for rows.Next() {
		var t domain.Ticket
		rows.Scan(&t.ID, &t.Title, &t.Severity, &t.Status)
		tickets = append(tickets, t)
	}
	return tickets, nil
}

// insertTicket writes one finding. CreateTicket (rules.go) runs the rules engine first.
func (s *SQLiteStore) insertTicket(ctx context.Context, t *domain.Ticket) error {
	if t.Status == "" {
		t.Status = "Waiting to be Triaged"
	}
	if t.Domain == "" {
		t.Domain = "Vulnerability"
	}
	if t.Source == "" {
		t.Source = "Manual"
	}
	if t.AssetIdentifier == "" {
		t.AssetIdentifier = "Default"
	}

	rawHash := t.Source + "|" + t.AssetIdentifier + "|" + t.Title
	hashBytes := sha256.Sum256([]byte(rawHash))
	t.DedupeHash = hex.EncodeToString(hashBytes[:])

	query := `
		INSERT INTO tickets (
			domain, source, asset_identifier, title, description, recommended_remediation,
			severity, status, dedupe_hash, cvss_vector, cvss_score, cwe, business_impact,
			triage_due_date, remediation_due_date, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	triageDue, remediationDue := s.dueDates(ctx, t.Domain, t.Severity)
	res, err := s.DB.ExecContext(ctx, query,
		t.Domain, t.Source, t.AssetIdentifier, t.Title, t.Description, t.RecommendedRemediation,
		t.Severity, t.Status, t.DedupeHash, t.CVSSVector, t.CVSSScore, t.CWE, t.BusinessImpact,
		triageDue, remediationDue,
	)

	if err != nil {
		return err
	}

	id, _ := res.LastInsertId()
	t.ID = int(id)
	return nil
}

// UpdateTicketInline handles a single UI edit and updates the flattened comment tracking
func (s *SQLiteStore) UpdateTicketInline(ctx context.Context, ticketID int, severity, description, remediation, comment, actor, status, assignee string) error {
	query := `
		UPDATE tickets 
		SET severity = ?, description = ?, recommended_remediation = ?, 
		    status = ?, assignee = ?, 
		    latest_comment = CASE WHEN ? != '' THEN ? ELSE latest_comment END,
		    updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?`

	formattedComment := ""
	if comment != "" {
		formattedComment = "[" + actor + "] " + comment
	}

	_, err := s.DB.ExecContext(ctx, query, severity, description, remediation, status, assignee, formattedComment, formattedComment, ticketID)
	return err
}

// RejectTicketFromWrangler puts a ticket back into the Holding Pen
func (s *SQLiteStore) RejectTicketFromWrangler(ctx context.Context, ticketIDs []int, reason, comment string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, id := range ticketIDs {
		fullComment := "[Wrangler Reject: " + reason + "] " + comment
		_, err := tx.ExecContext(ctx, "UPDATE tickets SET status = 'Returned to Security', assignee = 'Unassigned', latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", fullComment, id)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetTicketByID(ctx context.Context, id int) (domain.Ticket, error) {
	var t domain.Ticket
	var triageDue, remDue, created, updated string
	var patchedAt *string

	var cvssVec, cwe, bizImpact sql.NullString
	var cvssScore sql.NullFloat64
	var rationale sql.NullString
	var extensions sql.NullInt64

	query := `SELECT id, domain, source, asset_identifier, title, description, recommended_remediation, severity, status, dedupe_hash, triage_due_date, remediation_due_date, created_at, updated_at, patched_at, assignee, latest_comment, cvss_vector, cvss_score, cwe, business_impact, risk_rationale, extension_count FROM tickets WHERE id = ?`

	err := s.DB.QueryRowContext(ctx, query, id).Scan(
		&t.ID, &t.Domain, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation, &t.Severity, &t.Status, &t.DedupeHash, &triageDue, &remDue, &created, &updated, &patchedAt, &t.Assignee, &t.LatestComment, &cvssVec, &cvssScore, &cwe, &bizImpact, &rationale, &extensions,
	)
	if err != nil {
		return t, err
	}
	t.RiskRationale = rationale.String
	t.ExtensionCount = int(extensions.Int64)
	t.CVSSVector = cvssVec.String
	t.CVSSScore = cvssScore.Float64
	t.CWE = cwe.String
	t.BusinessImpact = bizImpact.String

	t.TriageDueDate, _ = time.Parse(time.RFC3339, triageDue)
	t.RemediationDueDate, _ = time.Parse(time.RFC3339, remDue)
	t.CreatedAt, _ = time.Parse(time.RFC3339, created)
	t.UpdatedAt, _ = time.Parse(time.RFC3339, updated)

	if patchedAt != nil {
		pTime, _ := time.Parse(time.RFC3339, *patchedAt)
		t.PatchedAt = &pTime
	}

	return t, nil
}
