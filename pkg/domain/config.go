package domain

type AppConfig struct {
	Timezone             string `json:"timezone"`
	BusinessStart        int    `json:"business_start"`
	BusinessEnd          int    `json:"business_end"`
	DefaultExtensionDays int    `json:"default_extension_days"`
}
