package domain

import "time"

// Asset is one row of the inventory: what the tool knows about a thing you
// run, beyond the findings that land on it. Exposure and criticality feed the
// priority rubric; owner and notes are shown to the person reading the queue.
type Asset struct {
	AssetIdentifier string    `json:"asset_identifier"`
	Exposure        string    `json:"exposure"`    // internet | internal | isolated
	Criticality     string    `json:"criticality"` // crown-jewel | standard | dev
	Owner           string    `json:"owner"`
	Notes           string    `json:"notes"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Exposures and Criticalities are the two scales the inventory accepts, in
// the order the book lists them. The schema enforces the same sets.
var (
	Exposures     = []string{"internet", "internal", "isolated"}
	Criticalities = []string{"crown-jewel", "standard", "dev"}
)

// RubricWeight is one number of the priority rubric: a base weight per scanner
// severity, a multiplier per exposure or criticality, or a band threshold.
type RubricWeight struct {
	Kind   string  `json:"kind"` // base | exposure | criticality | band
	Key    string  `json:"key"`
	Weight float64 `json:"weight"`
}

// RubricOrder is the display order of the fourteen weights.
var RubricOrder = []RubricWeight{
	{Kind: "base", Key: "Critical"}, {Kind: "base", Key: "High"}, {Kind: "base", Key: "Medium"}, {Kind: "base", Key: "Low"}, {Kind: "base", Key: "Info"},
	{Kind: "exposure", Key: "internet"}, {Kind: "exposure", Key: "internal"}, {Kind: "exposure", Key: "isolated"},
	{Kind: "criticality", Key: "crown-jewel"}, {Kind: "criticality", Key: "standard"}, {Kind: "criticality", Key: "dev"},
	{Kind: "band", Key: "Critical"}, {Kind: "band", Key: "High"}, {Kind: "band", Key: "Medium"},
}
