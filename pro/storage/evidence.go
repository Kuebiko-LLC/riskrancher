package storage

import (
	"context"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// AddEvidence stores a processed image (web + thumbnail blobs) for a finding and
// sets the new id on the metadata struct.
func (s *ProSQLiteStore) AddEvidence(ctx context.Context, ev *proModels.Evidence, web, thumb []byte) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO evidence (ticket_id, caption, content_type, width, height, size, image_data, thumb_data, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TicketID, ev.Caption, ev.ContentType, ev.Width, ev.Height, ev.Size, web, thumb, ev.CreatedBy)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	ev.ID = int(id)
	_ = s.db.QueryRowContext(ctx, `SELECT created_at FROM evidence WHERE id = ?`, ev.ID).Scan(&ev.CreatedAt)
	return ev.ID, nil
}

// ListEvidenceForTicket returns evidence metadata (no blobs) for a finding.
func (s *ProSQLiteStore) ListEvidenceForTicket(ctx context.Context, ticketID int) ([]proModels.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ticket_id, caption, content_type, width, height, size, created_by, created_at
		FROM evidence WHERE ticket_id = ? ORDER BY id`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []proModels.Evidence
	for rows.Next() {
		var e proModels.Evidence
		if err := rows.Scan(&e.ID, &e.TicketID, &e.Caption, &e.ContentType, &e.Width, &e.Height, &e.Size, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEvidenceMeta returns one evidence row's metadata (no blobs), for auth and
// display.
func (s *ProSQLiteStore) GetEvidenceMeta(ctx context.Context, id int) (*proModels.Evidence, error) {
	var e proModels.Evidence
	err := s.db.QueryRowContext(ctx, `
		SELECT id, ticket_id, caption, content_type, width, height, size, created_by, created_at
		FROM evidence WHERE id = ?`, id,
	).Scan(&e.ID, &e.TicketID, &e.Caption, &e.ContentType, &e.Width, &e.Height, &e.Size, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// GetEvidenceBlob returns the web image (or thumbnail when thumb is true) bytes
// and content type for serving.
func (s *ProSQLiteStore) GetEvidenceBlob(ctx context.Context, id int, thumb bool) ([]byte, string, error) {
	col := "image_data"
	if thumb {
		col = "thumb_data"
	}
	var data []byte
	var ct string
	err := s.db.QueryRowContext(ctx, `SELECT `+col+`, content_type FROM evidence WHERE id = ?`, id).Scan(&data, &ct)
	if err != nil {
		return nil, "", err
	}
	return data, ct, nil
}

// DeleteEvidence removes one evidence row.
func (s *ProSQLiteStore) DeleteEvidence(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM evidence WHERE id = ?`, id)
	return err
}

// EngagementOwnerForTicket returns the owner_email of the engagement a finding
// belongs to (empty string + nil if the finding is not in an engagement).
func (s *ProSQLiteStore) EngagementOwnerForTicket(ctx context.Context, ticketID int) (string, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, `
		SELECT e.owner_email
		FROM tickets t JOIN engagements e ON e.id = t.engagement_id
		WHERE t.id = ?`, ticketID).Scan(&owner)
	if err != nil {
		return "", err
	}
	return owner, nil
}
