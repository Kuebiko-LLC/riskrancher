package domain

type DraftTicket struct {
	ID                     int    `json:"id"`
	ReportID               string `json:"report_id"`
	Title                  string `json:"title"`
	Description            string `json:"description"`
	Severity               string `json:"severity"`
	AssetIdentifier        string `json:"asset_identifier"`
	RecommendedRemediation string `json:"recommended_remediation"`
}
