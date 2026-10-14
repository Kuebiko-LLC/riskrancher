package datastore

import (
	"context"
	"fmt"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (s *SQLiteStore) SaveDraft(ctx context.Context, d domain2.DraftTicket) error {
	query := `
		INSERT INTO draft_tickets (report_id, title, description, severity, asset_identifier, recommended_remediation) 
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := s.DB.ExecContext(ctx, query,
		d.ReportID, d.Title, d.Description, d.Severity, d.AssetIdentifier, d.RecommendedRemediation)
	return err
}

func (s *SQLiteStore) GetDraftsByReport(ctx context.Context, reportID string) ([]domain2.DraftTicket, error) {

	query := `SELECT id, report_id, COALESCE(title, ''), COALESCE(description, ''), COALESCE(severity, 'Medium'), COALESCE(asset_identifier, ''), COALESCE(recommended_remediation, '') 
	          FROM draft_tickets WHERE report_id = ?`

	rows, err := s.DB.QueryContext(ctx, query, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var drafts []domain2.DraftTicket
	for rows.Next() {
		var d domain2.DraftTicket
		if err := rows.Scan(&d.ID, &d.ReportID, &d.Title, &d.Description, &d.Severity, &d.AssetIdentifier, &d.RecommendedRemediation); err == nil {
			drafts = append(drafts, d)
		}
	}

	if drafts == nil {
		drafts = []domain2.DraftTicket{}
	}
	return drafts, nil
}

func (s *SQLiteStore) DeleteDraft(ctx context.Context, draftID string) error {
	query := `DELETE FROM draft_tickets WHERE id = ?`
	_, err := s.DB.ExecContext(ctx, query, draftID)
	return err
}

func (s *SQLiteStore) UpdateDraft(ctx context.Context, draftID int, payload domain2.Ticket) error {
	query := `UPDATE draft_tickets SET title = ?, severity = ?, asset_identifier = ?, description = ?, recommended_remediation = ? WHERE id = ?`

	_, err := s.DB.ExecContext(
		ctx,
		query,
		payload.Title,
		payload.Severity,
		payload.AssetIdentifier,
		payload.Description,
		payload.RecommendedRemediation,
		draftID,
	)

	return err
}

func (s *SQLiteStore) PromotePentestDrafts(ctx context.Context, reportID string, analystEmail string, tickets []domain2.Ticket) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, t := range tickets {
		hash := fmt.Sprintf("manual-pentest-%s-%s", t.AssetIdentifier, t.Title)

		promoteTriageDue, promoteRemediationDue := s.dueDates(ctx, "", t.Severity)
		res, err := tx.ExecContext(ctx, `
			INSERT INTO tickets (
				source, asset_identifier, title, description, recommended_remediation, severity, status, dedupe_hash,
				triage_due_date, remediation_due_date, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, 'Waiting to be Triaged', ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, "Manual Pentest", t.AssetIdentifier, t.Title, t.Description, t.RecommendedRemediation, t.Severity, hash, promoteTriageDue, promoteRemediationDue)
		if err != nil {
			return err
		}

		ticketID, err := res.LastInsertId()
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO ticket_assignments (ticket_id, assignee, role)
			VALUES (?, ?, 'RangeHand')
		`, ticketID, analystEmail)
		if err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM draft_tickets WHERE report_id = ?", reportID)
	if err != nil {
		return err
	}

	return tx.Commit()
}
