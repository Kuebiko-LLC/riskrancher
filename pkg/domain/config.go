package domain

type AppConfig struct {
	Timezone             string       `json:"timezone"`
	BusinessStart        int          `json:"business_start"`
	BusinessEnd          int          `json:"business_end"`
	DefaultExtensionDays int          `json:"default_extension_days"`
	Backup               BackupPolicy `json:"backup"`
}

type BackupPolicy struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"`
	RetentionDays int  `json:"retention_days"`
}
