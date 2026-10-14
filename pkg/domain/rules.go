package domain

import (
	"time"
)

// SuppressionRule silences known False Positives forever
type SuppressionRule struct {
	ID              int       `json:"id"`
	DedupeHash      string    `json:"dedupe_hash"`
	AssetIdentifier string    `json:"asset_identifier"`
	Rationale       string    `json:"rationale"`
	Actor           string    `json:"actor"`
	CreatedAt       time.Time `json:"created_at"`
}

// RoutingRule automatically assigns incoming tickets
type RoutingRule struct {
	ID         int       `json:"id"`
	RuleType   string    `json:"rule_type"`
	MatchValue string    `json:"match_value"`
	Assignee   string    `json:"assignee"`
	Role       string    `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
}

// AutoTriageRule mutates ticket severity based on assets/sources
type AutoTriageRule struct {
	ID          int       `json:"id"`
	MatchSource string    `json:"match_source"`
	MatchAsset  string    `json:"match_asset"`
	MatchCVE    string    `json:"match_cve"`
	ActionType  string    `json:"action_type"`
	ActionValue string    `json:"action_value"`
	CreatedAt   time.Time `json:"created_at"`
}

// CISAFeed is the CISA KEV catalog JSON schema
type CISAFeed struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
		// We ignore the rest of the fields to save memory
	} `json:"vulnerabilities"`
}

// APIKey represents a Service Account token for automated systems
type APIKey struct {
	ID          int        `json:"id"`
	TokenHash   string     `json:"-"` // Never expose the hash via JSON
	Name        string     `json:"name"`
	Permissions string     `json:"permissions"` // WriteOnly, ReadOnly, FullAdmin
	CreatedBy   int        `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}
