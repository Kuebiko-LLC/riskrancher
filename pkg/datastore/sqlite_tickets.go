package datastore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// GetTickets lists released findings for the API: enough to act on each one
// (asset, source, owner, status, clock), oldest first, a page at a time.
func (s *SQLiteStore) GetTickets(ctx context.Context, limit, offset int) ([]domain.Ticket, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, domain, source, asset_identifier, title, severity, status, COALESCE(assignee, 'Unassigned'), remediation_due_date, COALESCE(is_cisa_kev, 0), created_at, updated_at
		FROM tickets WHERE released = 1 ORDER BY id LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tickets := []domain.Ticket{}
	for rows.Next() {
		var t domain.Ticket
		var due sql.NullTime
		if err := rows.Scan(&t.ID, &t.Domain, &t.Source, &t.AssetIdentifier, &t.Title, &t.Severity, &t.Status, &t.Assignee, &due, &t.IsCISAKEV, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.RemediationDueDate = due.Time
		tickets = append(tickets, t)
	}
	return tickets, rows.Err()
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
			is_cisa_kev, triage_due_date, remediation_due_date, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	triageDue, remediationDue := s.dueDates(ctx, t.Domain, t.Severity)
	res, err := s.DB.ExecContext(ctx, query,
		t.Domain, t.Source, t.AssetIdentifier, t.Title, t.Description, t.RecommendedRemediation,
		t.Severity, t.Status, t.DedupeHash, t.CVSSVector, t.CVSSScore, t.CWE, t.BusinessImpact,
		t.IsCISAKEV, triageDue, remediationDue,
	)

	if err != nil {
		return err
	}

	id, _ := res.LastInsertId()
	t.ID = int(id)
	return nil
}

// UpdateTicketInline is a single edit from the dashboard drawer. Every field
// is optional: an empty value leaves the column as it is, so an edit to the
// severity or the text never touches the finding's status or owner.
func (s *SQLiteStore) UpdateTicketInline(ctx context.Context, ticketID int, severity, description, remediation, comment, actor, status, assignee string) error {
	query := `
		UPDATE tickets
		SET severity = CASE WHEN ? != '' THEN ? ELSE severity END,
		    description = CASE WHEN ? != '' THEN ? ELSE description END,
		    recommended_remediation = CASE WHEN ? != '' THEN ? ELSE recommended_remediation END,
		    status = CASE WHEN ? != '' THEN ? ELSE status END,
		    patched_at = CASE WHEN ? = 'Patched' THEN CURRENT_TIMESTAMP WHEN ? != '' THEN NULL ELSE patched_at END,
		    assignee = CASE WHEN ? != '' THEN ? ELSE assignee END,
		    latest_comment = CASE WHEN ? != '' THEN ? ELSE latest_comment END,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	formattedComment := ""
	if comment != "" {
		formattedComment = "[" + actor + "] " + comment
	}
	if severity != "" {
		severity = domain.NormalizeSeverity(severity)
	}

	_, err := s.DB.ExecContext(ctx, query,
		severity, severity, description, description, remediation, remediation,
		status, status, status, status, assignee, assignee, formattedComment, formattedComment, ticketID)
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
	var kev sql.NullBool
	var expires sql.NullTime

	query := `SELECT id, domain, source, asset_identifier, title, description, recommended_remediation, severity, status, dedupe_hash, triage_due_date, remediation_due_date, created_at, updated_at, patched_at, assignee, latest_comment, cvss_vector, cvss_score, cwe, business_impact, risk_rationale, extension_count, is_cisa_kev, exception_expires_at FROM tickets WHERE id = ?`

	err := s.DB.QueryRowContext(ctx, query, id).Scan(
		&t.ID, &t.Domain, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation, &t.Severity, &t.Status, &t.DedupeHash, &triageDue, &remDue, &created, &updated, &patchedAt, &t.Assignee, &t.LatestComment, &cvssVec, &cvssScore, &cwe, &bizImpact, &rationale, &extensions, &kev, &expires,
	)
	if err != nil {
		return t, err
	}
	t.RiskRationale = rationale.String
	t.ExtensionCount = int(extensions.Int64)
	t.IsCISAKEV = kev.Bool
	if expires.Valid {
		exp := expires.Time
		t.ExceptionExpiresAt = &exp
	}
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
