package domain

type ResolutionMetrics struct {
	Total         int
	Patched       int
	RiskAccepted  int
	FalsePositive int
	PatchedPct    int
	RiskAccPct    int
	FalsePosPct   int
}

type SheriffAnalytics struct {
	ActiveKEVs     int
	GlobalMTTRDays int
	OpenCriticals  int
	TotalOverdue   int
	SourceHealth   []SourceMetrics
	Resolution     ResolutionMetrics
	Severity       SeverityMetrics
	TopAssets      []AssetMetric
}

type SourceMetrics struct {
	Source        string
	TotalOpen     int
	Criticals     int
	CisaKEVs      int
	Untriaged     int
	PatchOverdue  int
	PendingRisk   int
	TotalClosed   int
	Patched       int
	RiskAccepted  int
	FalsePositive int
	TopAssignee   string
	StrategicNote string
}

type FeedItem struct {
	Actor        string
	ActivityType string
	NewValue     string
	TimeAgo      string
}

type SeverityMetrics struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
	CritPct  int
	HighPct  int
	MedPct   int
	LowPct   int
	InfoPct  int
}

type AssetMetric struct {
	Asset      string
	Count      int
	Percentage int
}

type SyncLog struct {
	ID               int    `json:"id"`
	Source           string `json:"source"`
	Status           string `json:"status"`
	RecordsProcessed int    `json:"records_processed"`
	ErrorMessage     string `json:"error_message"`
	CreatedAt        string `json:"created_at"`
}
