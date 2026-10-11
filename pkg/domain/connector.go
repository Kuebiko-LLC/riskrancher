package domain

// ConnectorTemplate defines how to translate third-party JSON into ticket format
type ConnectorTemplate struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SourceDefault     string `json:"source_default"`
	FindingsArrayPath string `json:"findings_array_path"`
	FieldMappings     struct {
		Title                  string `json:"title"`
		AssetIdentifier        string `json:"asset_identifier"`
		Severity               string `json:"severity"`
		Description            string `json:"description"`
		RecommendedRemediation string `json:"recommended_remediation"`
	} `json:"field_mappings"`
}
