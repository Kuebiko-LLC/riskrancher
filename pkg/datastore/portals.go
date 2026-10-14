package datastore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// ErrExtensionCapReached is returned when a finding has already had every
// extension its SLA policy allows.
var ErrExtensionCapReached = errors.New("extension cap reached for this severity")

// GetMagicBatch resolves a portal link. Unknown, revoked and expired links are errors.
func (s *SQLiteStore) GetMagicBatch(ctx context.Context, token string) (*domain.MagicBatch, error) {
	var b domain.MagicBatch
	var idsJSON string
	var revoked bool
	err := s.DB.QueryRowContext(ctx, `SELECT token, created_by, expires_at, is_revoked, kind, ticket_ids FROM magic_batches WHERE token = ?`, token).
		Scan(&b.Token, &b.CreatedBy, &b.ExpiresAt, &revoked, &b.Kind, &idsJSON)
	if err != nil {
		return nil, fmt.Errorf("unknown link")
	}
	if revoked {
		return nil, fmt.Errorf("link revoked")
	}
	if b.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("link expired")
	}
	if err := json.Unmarshal([]byte(idsJSON), &b.TicketIDs); err != nil {
		return nil, err
	}
	return &b, nil
}

// MintApproverLink is the Sheriff handing a request to the person who signs:
// a link of its own kind over the findings waiting for a decision, with the
// Sheriff's context written where the approver's page reads it.
func (s *SQLiteStore) MintApproverLink(ctx context.Context, ids []int, actor, context string) (string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var pending []int
	for _, id := range ids {
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM tickets WHERE id = ?`, id).Scan(&status); err != nil {
			return "", err
		}
		if status != "Pending Risk Approval" {
			continue
		}
		pending = append(pending, id)
		if context != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, "Security context: "+context, id); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'security_context', ?)`, id, actor, context); err != nil {
				return "", err
			}
		}
	}
	if len(pending) == 0 {
		return "", fmt.Errorf("none of these findings is waiting for a decision")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	idsJSON, _ := json.Marshal(pending)
	if _, err := tx.ExecContext(ctx, `INSERT INTO magic_batches (token, created_by, expires_at, kind, ticket_ids) VALUES (?, ?, DATETIME('now', '+90 days'), 'approver', ?)`, token, actor, string(idsJSON)); err != nil {
		return "", err
	}
	return token, tx.Commit()
}

// TicketsByIDs loads findings in id order.
func (s *SQLiteStore) TicketsByIDs(ctx context.Context, ids []int) ([]domain.Ticket, error) {
	out := []domain.Ticket{}
	for _, id := range ids {
		t, err := s.GetTicketByID(ctx, id)
		if err == nil {
			out = append(out, t)
		}
	}
	return out, nil
}

// SubmitPortalFix is the owner saying "done": the finding waits for verification with the evidence attached.
func (s *SQLiteStore) SubmitPortalFix(ctx context.Context, ids []int, evidence, actor string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Pending Verification', patch_evidence = ?, latest_comment = ?, verification_requested_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, evidence, "Fix submitted: "+evidence, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'fix_submitted', ?)`, id, actor, evidence); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RequestRiskException is the owner asking for more time or for the risk to be accepted.
func (s *SQLiteStore) RequestRiskException(ctx context.Context, ids []int, kind, rationale, actor string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Pending Risk Approval', risk_rationale = ?, latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, kind+": "+rationale, "Requested "+kind+": "+rationale, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'risk_requested', ?)`, id, actor, kind+": "+rationale); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReviewRiskRequest is the approver's decision on findings waiting for one.
// Approve on a time-extension request moves the clock by days, within the SLA
// policy's cap; Approve on anything else accepts the risk until an expiry days
// out. Deny hands the finding back to its owner with the reason.
func (s *SQLiteStore) ReviewRiskRequest(ctx context.Context, ids []int, action, actor, comment string, days int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if days <= 0 {
		if err := tx.QueryRowContext(ctx, `SELECT default_extension_days FROM app_config WHERE id = 1`).Scan(&days); err != nil || days <= 0 {
			days = 30
		}
	}
	for _, id := range ids {
		var status, domainName, severity string
		var rationale sql.NullString
		var extensions sql.NullInt64
		var due sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT status, domain, severity, risk_rationale, extension_count, remediation_due_date FROM tickets WHERE id = ?`, id).Scan(&status, &domainName, &severity, &rationale, &extensions, &due); err != nil {
			return err
		}
		if status != "Pending Risk Approval" {
			continue
		}
		switch action {
		case "Approve":
			if strings.HasPrefix(rationale.String, "Time Extension") {
				var maxExt sql.NullInt64
				tx.QueryRowContext(ctx, `SELECT max_extensions FROM sla_policies WHERE domain = ? AND severity = ?`, domainName, severity).Scan(&maxExt)
				if maxExt.Valid && extensions.Int64 >= maxExt.Int64 {
					return ErrExtensionCapReached
				}
				from := time.Now()
				if due.Valid {
					from = due.Time
				}
				newDue := from.AddDate(0, 0, days)
				if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Assigned Out', remediation_due_date = ?, extension_count = ?, risk_approved_by = ?, risk_approved_at = CURRENT_TIMESTAMP, latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, newDue, extensions.Int64+1, actor, "Extension approved: "+comment, id); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'extension_approved', ?)`, id, actor, fmt.Sprintf("%d days: %s", days, comment)); err != nil {
					return err
				}
			} else {
				if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Risk Accepted', risk_approved_by = ?, risk_approved_at = CURRENT_TIMESTAMP, exception_expires_at = ?, latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, actor, time.Now().AddDate(0, 0, days), "Risk accepted: "+comment, id); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'risk_accepted', ?)`, id, actor, fmt.Sprintf("expires in %d days: %s", days, comment)); err != nil {
					return err
				}
			}
		case "Deny":
			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Assigned Out', latest_comment = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, "Request denied: "+comment, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'risk_denied', ?)`, id, actor, comment); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action %q", action)
		}
	}
	return tx.Commit()
}

// ReopenExpiredExceptions is the sweep: an accepted risk is deferred, not
// closed, and when its expiry passes it returns to the queue with a fresh
// clock from the SLA matrix and a line in the activity.
func (s *SQLiteStore) ReopenExpiredExceptions(ctx context.Context) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, domain, severity FROM tickets WHERE status = 'Risk Accepted' AND exception_expires_at IS NOT NULL AND exception_expires_at <= CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	type due struct {
		id               int
		domain, severity string
	}
	var expired []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.domain, &d.severity); err == nil {
			expired = append(expired, d)
		}
	}
	rows.Close()
	if len(expired) == 0 {
		return 0, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, d := range expired {
		triageDue, remediationDue := s.dueDates(ctx, d.domain, d.severity)
		if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Waiting to be Triaged', exception_expires_at = NULL, triage_due_date = ?, remediation_due_date = ?, latest_comment = 'Risk acceptance expired: back on the queue for a fresh look', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, triageDue, remediationDue, d.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) VALUES (?, 'Expiry sweep', 'exception_expired', 'Risk Accepted', 'Waiting to be Triaged')`, d.id); err != nil {
			return 0, err
		}
	}
	return len(expired), tx.Commit()
}
