package domain

type ExportState struct {
	AppConfig   AppConfig   `json:"app_config"`
	SLAPolicies []SLAPolicy `json:"sla_policies"`
	Users       []User      `json:"users"`
	Adapters    []Adapter   `json:"adapters"`
	Tickets     []Ticket    `json:"tickets"`
	Version     string      `json:"export_version"`
	ExportedAt  string      `json:"exported_at"`
}
