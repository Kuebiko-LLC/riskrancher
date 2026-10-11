package domain

// Adapter represents a saved mapping profile for a specific scanner
type Adapter struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	SourceName         string `json:"source_name"`
	FindingsPath       string `json:"findings_path"`
	MappingTitle       string `json:"mapping_title"`
	MappingAsset       string `json:"mapping_asset"`
	MappingSeverity    string `json:"mapping_severity"`
	MappingDescription string `json:"mapping_description"`
	MappingRemediation string `json:"mapping_remediation"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}
