package domain

import "time"

// SeverityProposal is a requested severity change on a Bounty-Hunter-origin
// finding. Because severity is a common point of conflict between the triager
// (RangeHand) and the pentester (Bounty Hunter), a RangeHand cannot silently
// re-rate a BH finding: they propose, the BH accepts or contests, and a
// contested proposal escalates to the Sheriff to adjudicate.
type SeverityProposal struct {
	ID             int        `json:"id"`
	TicketID       int        `json:"ticket_id"`
	FromSeverity   string     `json:"from_severity"`
	ToSeverity     string     `json:"to_severity"`
	Justification  string     `json:"justification"`
	ProposedBy     string     `json:"proposed_by"`
	Status         string     `json:"status"` // Pending | Accepted | Contested | Resolved
	ResolvedBy     string     `json:"resolved_by,omitempty"`
	ResolutionNote string     `json:"resolution_note,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}
