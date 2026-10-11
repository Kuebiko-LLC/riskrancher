package storage

import (
	"context"
	"database/sql"
	"errors"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// ErrNotBountyHunterFinding is returned when a severity-change proposal is
// attempted on a finding that did not come from a Bounty Hunter engagement.
// Those findings are re-rated directly, not by proposal.
var ErrNotBountyHunterFinding = errors.New("finding is not from a Bounty Hunter engagement; edit severity directly")

// ErrProposalNotPending / ErrProposalNotContested guard the proposal state
// machine: accept/contest act only on Pending, adjudicate only on Contested.
var (
	ErrProposalNotPending   = errors.New("proposal is not pending")
	ErrProposalNotContested = errors.New("proposal is not contested")
)

// txResolve applies a final severity to the finding and resolves the proposal
// in one transaction, so a partial failure cannot leave them out of sync.
func (s *ProSQLiteStore) txResolve(ctx context.Context, ticketID int, newSeverity string, proposalID int, status, actor, note string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE tickets SET severity = ? WHERE id = ?`, newSeverity, ticketID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE severity_proposals SET status = ?, resolved_by = ?, resolution_note = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
		status, actor, note, proposalID); err != nil {
		return err
	}
	return tx.Commit()
}

// EngagementOwnerForProposal returns the owner_email of the engagement the
// proposal's finding belongs to, for owner-only authorization checks.
func (s *ProSQLiteStore) EngagementOwnerForProposal(ctx context.Context, proposalID int) (string, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, `
		SELECT e.owner_email
		FROM severity_proposals sp
		JOIN tickets t ON t.id = sp.ticket_id
		JOIN engagements e ON e.id = t.engagement_id
		WHERE sp.id = ?`, proposalID).Scan(&owner)
	return owner, err
}

const sevProposalCols = `id, ticket_id, from_severity, to_severity, justification, proposed_by, status, resolved_by, resolution_note, created_at, resolved_at`

func scanSevProposal(row interface{ Scan(...any) error }) (*proModels.SeverityProposal, error) {
	var p proModels.SeverityProposal
	var from, resolvedBy, resolutionNote sql.NullString
	var resolvedAt sql.NullTime
	if err := row.Scan(&p.ID, &p.TicketID, &from, &p.ToSeverity, &p.Justification, &p.ProposedBy, &p.Status, &resolvedBy, &resolutionNote, &p.CreatedAt, &resolvedAt); err != nil {
		return nil, err
	}
	p.FromSeverity = from.String
	p.ResolvedBy = resolvedBy.String
	p.ResolutionNote = resolutionNote.String
	if resolvedAt.Valid {
		p.ResolvedAt = &resolvedAt.Time
	}
	return &p, nil
}

func (s *ProSQLiteStore) logActivity(ctx context.Context, ticketID int, actor, activityType, oldVal, newVal string) {
	s.db.ExecContext(ctx,
		`INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) VALUES (?, ?, ?, ?, ?)`,
		ticketID, actor, activityType, oldVal, newVal)
}

// ProposeSeverityChange records a RangeHand's proposed severity change on a
// BH-origin finding. It does NOT change the severity; it records a Pending
// proposal and logs the request. Returns ErrNotBountyHunterFinding if the
// finding is not tied to an engagement.
func (s *ProSQLiteStore) ProposeSeverityChange(ctx context.Context, ticketID int, toSeverity, justification, proposedBy string) (*proModels.SeverityProposal, error) {
	var engagementID sql.NullInt64
	var fromSeverity string
	err := s.db.QueryRowContext(ctx, `SELECT engagement_id, severity FROM tickets WHERE id = ?`, ticketID).Scan(&engagementID, &fromSeverity)
	if err != nil {
		return nil, err
	}
	if !engagementID.Valid {
		return nil, ErrNotBountyHunterFinding
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO severity_proposals (ticket_id, from_severity, to_severity, justification, proposed_by, status)
		VALUES (?, ?, ?, ?, ?, 'Pending')`, ticketID, fromSeverity, toSeverity, justification, proposedBy)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.logActivity(ctx, ticketID, proposedBy, "severity_proposed", fromSeverity, toSeverity)
	return s.GetSeverityProposal(ctx, int(id))
}

// GetSeverityProposal returns one proposal by id.
func (s *ProSQLiteStore) GetSeverityProposal(ctx context.Context, id int) (*proModels.SeverityProposal, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+sevProposalCols+` FROM severity_proposals WHERE id = ?`, id)
	return scanSevProposal(row)
}

// ListProposalsForTicket returns a finding's full proposal history, oldest first.
func (s *ProSQLiteStore) ListProposalsForTicket(ctx context.Context, ticketID int) ([]proModels.SeverityProposal, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sevProposalCols+` FROM severity_proposals WHERE ticket_id = ? ORDER BY id`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSevProposals(rows)
}

// AcceptSeverityProposal (called by the owning Bounty Hunter) applies the
// proposed severity to the finding and resolves the proposal.
func (s *ProSQLiteStore) AcceptSeverityProposal(ctx context.Context, proposalID int, actor string) error {
	p, err := s.GetSeverityProposal(ctx, proposalID)
	if err != nil {
		return err
	}
	if p.Status != "Pending" {
		return ErrProposalNotPending
	}
	if err := s.txResolve(ctx, p.TicketID, p.ToSeverity, proposalID, "Accepted", actor, ""); err != nil {
		return err
	}
	s.logActivity(ctx, p.TicketID, actor, "severity_accepted", p.FromSeverity, p.ToSeverity)
	return nil
}

// ContestSeverityProposal (called by the owning Bounty Hunter) escalates a
// proposal to the Sheriff without changing the severity.
func (s *ProSQLiteStore) ContestSeverityProposal(ctx context.Context, proposalID int, actor, note string) error {
	p, err := s.GetSeverityProposal(ctx, proposalID)
	if err != nil {
		return err
	}
	if p.Status != "Pending" {
		return ErrProposalNotPending
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE severity_proposals SET status = 'Contested' WHERE id = ?`, proposalID); err != nil {
		return err
	}
	s.logActivity(ctx, p.TicketID, actor, "severity_contested", p.ToSeverity, note)
	return nil
}

// AdjudicateSeverityProposal (called by the Sheriff) breaks the tie: it applies
// the Sheriff's final severity and resolves the proposal.
func (s *ProSQLiteStore) AdjudicateSeverityProposal(ctx context.Context, proposalID int, finalSeverity, actor, note string) error {
	p, err := s.GetSeverityProposal(ctx, proposalID)
	if err != nil {
		return err
	}
	if p.Status != "Contested" {
		return ErrProposalNotContested
	}
	if err := s.txResolve(ctx, p.TicketID, finalSeverity, proposalID, "Resolved", actor, note); err != nil {
		return err
	}
	s.logActivity(ctx, p.TicketID, actor, "severity_adjudicated", p.FromSeverity, finalSeverity)
	return nil
}

// ListPendingProposalsForOwner returns the Pending proposals on findings in
// engagements owned by ownerEmail: the Bounty Hunter's alert feed.
func (s *ProSQLiteStore) ListPendingProposalsForOwner(ctx context.Context, ownerEmail string) ([]proModels.SeverityProposal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+prefixedSevCols("sp")+`
		FROM severity_proposals sp
		JOIN tickets t ON t.id = sp.ticket_id
		JOIN engagements e ON e.id = t.engagement_id
		WHERE e.owner_email = ? AND sp.status = 'Pending'
		ORDER BY sp.id DESC`, ownerEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSevProposals(rows)
}

// ListContestedProposals returns all contested proposals awaiting a Sheriff's
// adjudication: the Sheriff's queue.
func (s *ProSQLiteStore) ListContestedProposals(ctx context.Context) ([]proModels.SeverityProposal, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sevProposalCols+` FROM severity_proposals WHERE status = 'Contested' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSevProposals(rows)
}

func prefixedSevCols(alias string) string {
	return alias + ".id, " + alias + ".ticket_id, " + alias + ".from_severity, " + alias + ".to_severity, " +
		alias + ".justification, " + alias + ".proposed_by, " + alias + ".status, " + alias + ".resolved_by, " +
		alias + ".resolution_note, " + alias + ".created_at, " + alias + ".resolved_at"
}

func collectSevProposals(rows *sql.Rows) ([]proModels.SeverityProposal, error) {
	var out []proModels.SeverityProposal
	for rows.Next() {
		p, err := scanSevProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}
