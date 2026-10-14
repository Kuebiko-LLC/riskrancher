package domain

import (
	"strings"
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

	PatchEvidence *string `json:"patch_evidence"`

	TriageDueDate      time.Time  `json:"triage_due_date"`
	RemediationDueDate time.Time  `json:"remediation_due_date"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	PatchedAt          *time.Time `json:"patched_at"`

	SLAString     string `json:"sla_string"`
	Assignee      string `json:"assignee"`
	LatestComment string `json:"latest_comment"`

	// Structured pentest fields (populated for report findings).
	CVSSVector     string  `json:"cvss_vector"`
	CVSSScore      float64 `json:"cvss_score"`
	CWE            string  `json:"cwe"`
	BusinessImpact string  `json:"business_impact"`
	RiskRationale  string  `json:"risk_rationale,omitempty"`
	ExtensionCount int     `json:"extension_count,omitempty"`
	// IsCISAKEV is set when the finding names a CVE in the loaded KEV catalog.
	IsCISAKEV bool `json:"is_cisa_kev"`
	// ExceptionExpiresAt is set when the risk was accepted: the date it comes back.
	ExceptionExpiresAt *time.Time `json:"exception_expires_at,omitempty"`
}

// TicketAssignment represents the many-to-many relationship
type TicketAssignment struct {
	TicketID int    `json:"ticket_id"`
	Assignee string `json:"assignee"`
	Role     string `json:"role"`
}

// DashboardTicket is a ticket as the dashboard shows it, with the portal token
// an owner can use to update it without an account.
type DashboardTicket struct {
	Ticket
	MagicToken string `json:"magic_token,omitempty"`
	// RequestKind is what the owner asked for on a finding waiting for review:
	// Time Extension or Risk Acceptance.
	RequestKind string `json:"request_kind,omitempty"`
}

// FindingDetails are the structured fields a pentester fills on a finding.
type FindingDetails struct {
	Severity       string
	Description    string
	Remediation    string
	CVSSVector     string
	CVSSScore      float64
	CWE            string
	BusinessImpact string
}

// MagicBatch is a portal link: a set of findings handed to someone without an
// account, valid until it expires or is revoked.
type MagicBatch struct {
	Token     string
	CreatedBy string
	ExpiresAt time.Time
	TicketIDs []int
}

// ActivityEntry is one line of a finding's history.
type ActivityEntry struct {
	Actor    string    `json:"actor"`
	Type     string    `json:"type"`
	OldValue string    `json:"old_value,omitempty"`
	NewValue string    `json:"new_value,omitempty"`
	At       time.Time `json:"at"`
}

// NormalizeSeverity maps a scanner's spelling of a severity onto the one the
// SLA matrix and the counts use. Unknown values pass through unchanged.
func NormalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low":
		return "Low"
	case "info", "informational", "information", "negligible", "unknown", "none":
		return "Info"
	}
	return strings.TrimSpace(raw)
}
