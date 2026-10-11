package storage

import (
	"context"
	"fmt"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// CreateEngagement inserts a new engagement, assigns it the next sequential
// number (ENG-0001, ENG-0002, ...), defaults it to Active, and sets the id and
// number back on the struct.
func (s *ProSQLiteStore) CreateEngagement(ctx context.Context, e *proModels.Engagement) (int, error) {
	if e.Status == "" {
		e.Status = "Active"
	}
	res, err := s.db.ExecContext(ctx, `
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
	if _, err := s.db.ExecContext(ctx, `UPDATE engagements SET number = ? WHERE id = ?`, e.Number, e.ID); err != nil {
		return 0, err
	}
	return e.ID, nil
}

// GetEngagement returns one engagement by id.
func (s *ProSQLiteStore) GetEngagement(ctx context.Context, id int) (*proModels.Engagement, error) {
	var e proModels.Engagement
	err := s.db.QueryRowContext(ctx, `
		SELECT id, number, name, client, owner_email, status, created_at
		FROM engagements WHERE id = ?`, id,
	).Scan(&e.ID, &e.Number, &e.Name, &e.Client, &e.OwnerEmail, &e.Status, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ListEngagements returns engagements newest-first.
func (s *ProSQLiteStore) ListEngagements(ctx context.Context) ([]proModels.Engagement, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, number, name, client, owner_email, status, created_at
		FROM engagements ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []proModels.Engagement
	for rows.Next() {
		var e proModels.Engagement
		if err := rows.Scan(&e.ID, &e.Number, &e.Name, &e.Client, &e.OwnerEmail, &e.Status, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ReleaseEngagement marks an engagement Released: its findings are now handed
// off to the RangeHand queue.
func (s *ProSQLiteStore) ReleaseEngagement(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE engagements SET status = 'Released' WHERE id = ?`, id)
	return err
}

// AddFindingsToEngagement links the given tickets to an engagement.
func (s *ProSQLiteStore) AddFindingsToEngagement(ctx context.Context, engagementID int, ticketIDs []int) error {
	for _, tid := range ticketIDs {
		if _, err := s.db.ExecContext(ctx, `UPDATE tickets SET engagement_id = ? WHERE id = ?`, engagementID, tid); err != nil {
			return err
		}
	}
	return nil
}

// ListEngagementFindings returns the findings (tickets) linked to an engagement.
func (s *ProSQLiteStore) ListEngagementFindings(ctx context.Context, engagementID int) ([]coredomain.Ticket, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source, asset_identifier, title, description, recommended_remediation, severity, status
		FROM tickets WHERE engagement_id = ? ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []coredomain.Ticket
	for rows.Next() {
		var t coredomain.Ticket
		if err := rows.Scan(&t.ID, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation, &t.Severity, &t.Status); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
