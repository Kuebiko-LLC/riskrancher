package datastore

import (
	"context"
	"fmt"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// CreateEngagement inserts a new engagement, assigns it the next sequential
// number (ENG-0001, ENG-0002, ...), defaults it to Active, and sets the id and
// number back on the struct.
func (s *SQLiteStore) CreateEngagement(ctx context.Context, e *domain.Engagement) (int, error) {
	if e.Status == "" {
		e.Status = "Active"
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO engagements (name, client, owner_email, status)
		VALUES (?, ?, ?, ?)`, e.Name, e.Client, e.OwnerEmail, e.Status)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	e.ID = int(id)
	e.Number = fmt.Sprintf("ENG-%04d", e.ID)
	if _, err := s.DB.ExecContext(ctx, `UPDATE engagements SET number = ? WHERE id = ?`, e.Number, e.ID); err != nil {
		return 0, err
	}
	// Populate the DB-assigned created_at so the response carries a real time.
	_ = s.DB.QueryRowContext(ctx, `SELECT created_at FROM engagements WHERE id = ?`, e.ID).Scan(&e.CreatedAt)
	return e.ID, nil
}

// GetEngagement returns one engagement by id.
func (s *SQLiteStore) GetEngagement(ctx context.Context, id int) (*domain.Engagement, error) {
	var e domain.Engagement
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, number, name, client, owner_email, status, created_at
		FROM engagements WHERE id = ?`, id,
	).Scan(&e.ID, &e.Number, &e.Name, &e.Client, &e.OwnerEmail, &e.Status, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ListEngagements returns engagements newest-first.
func (s *SQLiteStore) ListEngagements(ctx context.Context) ([]domain.Engagement, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, number, name, client, owner_email, status, created_at
		FROM engagements ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Engagement
	for rows.Next() {
		var e domain.Engagement
		if err := rows.Scan(&e.ID, &e.Number, &e.Name, &e.Client, &e.OwnerEmail, &e.Status, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ReleaseEngagement marks an engagement Released and hands its findings off to
// the RangeHand queue (released = 1 makes them visible).
func (s *SQLiteStore) ReleaseEngagement(ctx context.Context, id int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE engagements SET status = 'Released' WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tickets SET released = 1 WHERE engagement_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// AddFindingsToEngagement links the given tickets to an engagement and holds
// them out of the triage queue (released = 0) until the engagement is released.
// Only unclaimed, untriaged findings qualify (engagement_id IS NULL AND status
// is still 'Waiting to be Triaged'), so a Bounty Hunter cannot hijack a finding
// that is already in another engagement or already being worked.
func (s *SQLiteStore) AddFindingsToEngagement(ctx context.Context, engagementID int, ticketIDs []int) error {
	if len(ticketIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(ticketIDs))
	args := make([]any, 0, len(ticketIDs)+1)
	args = append(args, engagementID)
	for i, tid := range ticketIDs {
		placeholders[i] = "?"
		args = append(args, tid)
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE tickets SET engagement_id = ?, released = 0
		 WHERE id IN (`+strings.Join(placeholders, ",")+`)
		   AND engagement_id IS NULL AND status = 'Waiting to be Triaged'`,
		args...)
	return err
}

// ListEngagementsByOwner returns the engagements owned by ownerEmail, newest first.
func (s *SQLiteStore) ListEngagementsByOwner(ctx context.Context, ownerEmail string) ([]domain.Engagement, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, number, name, client, owner_email, status, created_at
		FROM engagements WHERE owner_email = ? ORDER BY id DESC`, ownerEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Engagement
	for rows.Next() {
		var e domain.Engagement
		if err := rows.Scan(&e.ID, &e.Number, &e.Name, &e.Client, &e.OwnerEmail, &e.Status, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEngagementFindings returns the findings (tickets) linked to an engagement.
func (s *SQLiteStore) ListEngagementFindings(ctx context.Context, engagementID int) ([]domain.Ticket, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, source, asset_identifier, title, description, recommended_remediation, severity, status,
		       cvss_vector, cvss_score, cwe, business_impact
		FROM tickets WHERE engagement_id = ? ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Ticket
	for rows.Next() {
		t, err := scanReportTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
