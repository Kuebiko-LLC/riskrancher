package datastore

import (
	"context"
	"crypto/sha256"
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

func (s *SQLiteStore) CreateTicket(ctx context.Context, t *domain.Ticket) error {
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
			severity, status, dedupe_hash,
			triage_due_date, remediation_due_date, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '+3 days'), DATETIME('now', '+14 days'), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	res, err := s.DB.ExecContext(ctx, query,
		t.Domain, t.Source, t.AssetIdentifier, t.Title, t.Description, t.RecommendedRemediation,
		t.Severity, t.Status, t.DedupeHash,
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

	query := `SELECT id, domain, source, asset_identifier, title, description, recommended_remediation, severity, status, dedupe_hash, triage_due_date, remediation_due_date, created_at, updated_at, patched_at, assignee, latest_comment FROM tickets WHERE id = ?`

	err := s.DB.QueryRowContext(ctx, query, id).Scan(
		&t.ID, &t.Domain, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation, &t.Severity, &t.Status, &t.DedupeHash, &triageDue, &remDue, &created, &updated, &patchedAt, &t.Assignee, &t.LatestComment,
	)
	if err != nil {
		return t, err
	}

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
