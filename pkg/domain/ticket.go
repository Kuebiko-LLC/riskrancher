package domain

import (
	"time"
)

// SLAPolicy represents the global SLA configuration per severity
type SLAPolicy struct {
	Domain          string `json:"domain"`
	Severity        string `json:"severity"`
	DaysToRemediate int    `json:"days_to_remediate"`
	MaxExtensions   int    `json:"max_extensions"`
	DaysToTriage    int    `json:"days_to_triage"`
}

// AssetRiskSummary holds the rolled-up vulnerability counts for a single asset
type AssetRiskSummary struct {
	AssetIdentifier string
	TotalActive     int
	Critical        int
	High            int
	Medium          int
	Low             int
	Info            int
}

type Ticket struct {
	ID                     int    `json:"id"`
	Domain                 string `json:"domain"`
	IsOverdue              bool   `json:"is_overdue"`
	DaysToResolve          *int   `json:"days_to_resolve"`
	Source                 string `json:"source"`
	AssetIdentifier        string `json:"asset_identifier"`
	Title                  string `json:"title"`
	Description            string `json:"description"`
	RecommendedRemediation string `json:"recommended_remediation"`
	Severity               string `json:"severity"`
	Status                 string `json:"status"`

	DedupeHash string `json:"dedupe_hash"`

	PatchEvidence *string    `json:"patch_evidence"`
	OwnerViewedAt *time.Time `json:"owner_viewed_at"`

	TriageDueDate      time.Time  `json:"triage_due_date"`
	RemediationDueDate time.Time  `json:"remediation_due_date"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	PatchedAt          *time.Time `json:"patched_at"`

	SLAString     string `json:"sla_string"`
	Assignee      string `json:"assignee"`
	LatestComment string `json:"latest_comment"`
}

// TicketAssignment represents the many-to-many relationship
type TicketAssignment struct {
	TicketID int    `json:"ticket_id"`
	Assignee string `json:"assignee"`
	Role     string `json:"role"`
}
