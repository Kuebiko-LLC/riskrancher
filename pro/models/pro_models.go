// File: RiskRancher/pro/models/pro_models.go
package models

import (
	"time"
)

// 💎 PRO: SuppressionRule silences known False Positives forever
type SuppressionRule struct {
	ID              int       `json:"id"`
	DedupeHash      string    `json:"dedupe_hash"`
	AssetIdentifier string    `json:"asset_identifier"`
	Rationale       string    `json:"rationale"`
	Actor           string    `json:"actor"`
	CreatedAt       time.Time `json:"created_at"`
}

// 💎 PRO: RoutingRule automatically assigns incoming tickets
type RoutingRule struct {
	ID          int       `json:"id"`
	WorkspaceID int       `json:"workspace_id"` // 🚀 FIX: Added missing WorkspaceID
	RuleType    string    `json:"rule_type"`
	MatchValue  string    `json:"match_value"`
	Assignee    string    `json:"assignee"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

// 💎 PRO: AutoTriageRule mutates ticket severity based on assets/sources
type AutoTriageRule struct {
	ID          int       `json:"id"`
	WorkspaceID int       `json:"workspace_id"`
	MatchSource string    `json:"match_source"`
	MatchAsset  string    `json:"match_asset"`
	MatchCVE    string    `json:"match_cve"`
	ActionType  string    `json:"action_type"`
	ActionValue string    `json:"action_value"`
	CreatedAt   time.Time `json:"created_at"`
}

// 💎 PRO: CISA KEV JSON Schema
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

// Add to File: RiskRancher/pro/models/pro_models.go

// 🤠 PRO: APIKey represents a Service Account token for automated systems
type APIKey struct {
	ID          int        `json:"id"`
	TokenHash   string     `json:"-"` // Never expose the hash via JSON
	WorkspaceID int        `json:"workspace_id"`
	Name        string     `json:"name"`
	Permissions string     `json:"permissions"` // WriteOnly, ReadOnly, FullAdmin
	CreatedBy   int        `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// Application represents the canonical "Big Picture" entity
type Application struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	BusinessCriticality string    `json:"business_criticality"`
	OwnerTeam           string    `json:"owner_team"`
	CreatedAt           time.Time `json:"created_at"`
}

// AssetAlias represents the raw string from a scanner (Trivy, Semgrep, etc.)
type AssetAlias struct {
	ID              int       `json:"id"`
	ApplicationID   string    `json:"application_id"`
	Alias           string    `json:"alias"`
	Layer           string    `json:"layer"`
	DiscoverySource string    `json:"discovery_source"`
	IsAiSuggested   bool      `json:"is_ai_suggested"`
	IsVerified      bool      `json:"is_verified"`
	CreatedAt       time.Time `json:"created_at"`
}

// MatchmakerProposal represents the AI's suggestion to merge an alias into an App
type MatchmakerProposal struct {
	ID                  int       `json:"id"`
	SourceAliasID       int       `json:"source_alias_id"`
	TargetApplicationID string    `json:"target_application_id"`
	ConfidenceScore     float64   `json:"confidence_score"`
	Status              string    `json:"status"`
	Reasoning           string    `json:"reasoning"`
	CreatedAt           time.Time `json:"created_at"`
}
