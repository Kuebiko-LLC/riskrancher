package models

import "time"

// FindingTemplate is a reusable blueprint for a finding: write the boilerplate
// once (title, severity, description, remediation), then apply it to an
// engagement to create a prefilled finding that the tester adapts per-asset.
type FindingTemplate struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"` // library name/search key
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	Tags        string    `json:"tags"` // comma-separated
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
