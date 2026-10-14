package domain

import (
	"context"
	"net/http"
	"time"
)

// Store is the whole persistence contract, one interface per area.
type Store interface {
	TicketStore
	WorkflowStore
	PortalStore
	RulesStore
	AuditStore
	ServiceAccountStore
	KEVStore
	EngagementStore
	ProposalStore
	TemplateStore
	EvidenceStore
	ReportStore
	IdentityStore
	IngestStore
	ConfigStore
	AnalyticsStore
	DraftStore
}

// TicketStore: ticket CRUD and workflow
type TicketStore interface {
	GetTickets(ctx context.Context) ([]Ticket, error)
	GetDashboardTickets(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]Ticket, int, map[string]int, error)
	CreateTicket(ctx context.Context, t *Ticket) error
	GetTicketByID(ctx context.Context, id int) (Ticket, error)
	UpdateTicketInline(ctx context.Context, ticketID int, severity, description, remediation, comment, actor, status, assignee string) error
}

// IdentityStore: Users, Sessions, and Dispatching
type IdentityStore interface {
	CreateUser(ctx context.Context, email, fullName, passwordHash, globalRole string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id int) (*User, error)
	GetAllUsers(ctx context.Context) ([]*User, error)
	GetUserCount(ctx context.Context) (int, error)
	UpdateUserPassword(ctx context.Context, id int, newPasswordHash string) error
	UpdateUserRole(ctx context.Context, id int, newRole string) error
	DeactivateUserAndReassign(ctx context.Context, userID int) error

	CreateSession(ctx context.Context, token string, userID int, expiresAt time.Time) error
	GetSession(ctx context.Context, token string) (*Session, error)
	DeleteSession(ctx context.Context, token string) error

	GetWranglers(ctx context.Context) ([]User, error)
}

// IngestStore: Scanners, Adapters, and Sync History
type IngestStore interface {
	IngestTickets(ctx context.Context, tickets []Ticket) error
	ProcessIngestionBatch(ctx context.Context, source string, assetIdentifier string, incoming []Ticket) error

	GetAdapters(ctx context.Context) ([]Adapter, error)
	GetAdapterByID(ctx context.Context, id int) (Adapter, error)
	GetAdapterByName(ctx context.Context, name string) (Adapter, error)
	SaveAdapter(ctx context.Context, adapter Adapter) error
	DeleteAdapter(ctx context.Context, id int) error

	LogSync(ctx context.Context, source, status string, records int, errMsg string) error
	GetRecentSyncLogs(ctx context.Context, limit int) ([]SyncLog, error)
}

// ConfigStore: Global System Settings
type ConfigStore interface {
	GetAppConfig(ctx context.Context) (AppConfig, error)
	UpdateAppConfig(ctx context.Context, config AppConfig) error
	GetSLAPolicies(ctx context.Context) ([]SLAPolicy, error)
	UpdateSLAPolicies(ctx context.Context, slas []SLAPolicy) error
	UpdateBackupPolicy(ctx context.Context, policy BackupPolicy) error
	ExportSystemState(ctx context.Context) (ExportState, error)
}

// AnalyticsStore: Audit Logs and KPI Metrics
type AnalyticsStore interface {
	GetSheriffAnalytics(ctx context.Context) (SheriffAnalytics, error)
	GetAnalyticsSummary(ctx context.Context) (map[string]int, error)
	GetGlobalActivityFeed(ctx context.Context, limit int) ([]FeedItem, error)
	GetPaginatedActivityFeed(ctx context.Context, filter string, limit int, offset int) ([]FeedItem, int, error)
}

// DraftStore: pentest report intake (docx parsing into draft findings)
type DraftStore interface {
	SaveDraft(ctx context.Context, draft DraftTicket) error
	GetDraftsByReport(ctx context.Context, reportID string) ([]DraftTicket, error)
	DeleteDraft(ctx context.Context, draftID string) error
	UpdateDraft(ctx context.Context, draftID int, payload Ticket) error
	PromotePentestDrafts(ctx context.Context, reportID string, analystEmail string, tickets []Ticket) error
}

type Authenticator interface {
	Middleware(next http.Handler) http.Handler
}

type SLACalculator interface {
	CalculateDueDate(severity string) *time.Time
	CalculateTrueSLAHours(ctx context.Context, ticketID int, store Store) (float64, error)
}

// WorkflowStore: bulk actions, portals, and the dashboard view with portal tokens
type WorkflowStore interface {
	BulkUpdateStatusAndAssign(ctx context.Context, ticketIDs []int, status, assignee, comment, actor string) (string, error)
	RejectTicketFromWrangler(ctx context.Context, ticketIDs []int, reason, comment string) error
	GetDashboardTicketsWithPortals(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]DashboardTicket, int, map[string]int, error)
}

// RulesStore: the ingest rules (suppression, severity, routing)
type RulesStore interface {
	CreateAutoTriageRule(ctx context.Context, rule *AutoTriageRule) error
	GetAutoTriageRules(ctx context.Context) ([]AutoTriageRule, error)
	DeleteAutoTriageRule(ctx context.Context, ruleID int) error
	CreateSuppressionRule(ctx context.Context, rule *SuppressionRule) error
	ListSuppressionRules(ctx context.Context) ([]SuppressionRule, error)
	DeleteSuppressionRule(ctx context.Context, id int) error
	CreateRoutingRule(ctx context.Context, rule *RoutingRule) error
	GetRoutingRules(ctx context.Context) ([]RoutingRule, error)
	DeleteRoutingRule(ctx context.Context, id int) error
}

// AuditStore: the immutable audit log
type AuditStore interface {
	LogAuditAction(ctx context.Context, actor, action, resource string, statusCode int, errorDetails, ip string) error
}

// ServiceAccountStore: API keys
type ServiceAccountStore interface {
	CreateAPIKey(ctx context.Context, key APIKey) (string, error)
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context) ([]APIKey, error)
	DeleteAPIKey(ctx context.Context, id int) error
}

// KEVStore: the CISA known-exploited catalog you load yourself
type KEVStore interface {
	SyncCISACatalog(ctx context.Context, feed *CISAFeed) error
}

// EngagementStore: a pentest engagement and its findings
type EngagementStore interface {
	CreateEngagement(ctx context.Context, e *Engagement) (int, error)
	GetEngagement(ctx context.Context, id int) (*Engagement, error)
	ListEngagements(ctx context.Context) ([]Engagement, error)
	ListEngagementsByOwner(ctx context.Context, ownerEmail string) ([]Engagement, error)
	ReleaseEngagement(ctx context.Context, id int) error
	UpdateFindingDetails(ctx context.Context, ticketID int, d FindingDetails) error
	AddFindingsToEngagement(ctx context.Context, engagementID int, ticketIDs []int) error
	ListEngagementFindings(ctx context.Context, engagementID int) ([]Ticket, error)
}

// ProposalStore: severity proposals between a RangeHand and a Bounty Hunter
type ProposalStore interface {
	ProposeSeverityChange(ctx context.Context, ticketID int, toSeverity, justification, proposedBy string) (*SeverityProposal, error)
	GetSeverityProposal(ctx context.Context, id int) (*SeverityProposal, error)
	ListProposalsForTicket(ctx context.Context, ticketID int) ([]SeverityProposal, error)
	AcceptSeverityProposal(ctx context.Context, proposalID int, actor string) error
	ContestSeverityProposal(ctx context.Context, proposalID int, actor, note string) error
	AdjudicateSeverityProposal(ctx context.Context, proposalID int, finalSeverity, actor, note string) error
	ListPendingProposalsForOwner(ctx context.Context, ownerEmail string) ([]SeverityProposal, error)
	ListContestedProposals(ctx context.Context) ([]SeverityProposal, error)
	EngagementOwnerForProposal(ctx context.Context, proposalID int) (string, error)
}

// TemplateStore: the reusable finding library
type TemplateStore interface {
	CreateFindingTemplate(ctx context.Context, t *FindingTemplate) (int, error)
	GetFindingTemplate(ctx context.Context, id int) (*FindingTemplate, error)
	ListFindingTemplates(ctx context.Context) ([]FindingTemplate, error)
	UpdateFindingTemplate(ctx context.Context, t *FindingTemplate) error
	DeleteFindingTemplate(ctx context.Context, id int) error
	CreateFindingFromTemplate(ctx context.Context, templateID, engagementID int, asset, actor string) (int, error)
}

// EvidenceStore: screenshots attached to findings
type EvidenceStore interface {
	AddEvidence(ctx context.Context, ev *Evidence, web, thumb []byte) (int, error)
	ListEvidenceForTicket(ctx context.Context, ticketID int) ([]Evidence, error)
	GetEvidenceMeta(ctx context.Context, id int) (*Evidence, error)
	GetEvidenceBlob(ctx context.Context, id int, thumb bool) ([]byte, string, error)
	DeleteEvidence(ctx context.Context, id int) error
	EngagementOwnerForTicket(ctx context.Context, ticketID int) (string, error)
}

// ReportStore: findings in, a deliverable out
type ReportStore interface {
	CreatePentestReport(ctx context.Context, report *PentestReport) (int, error)
	UpdateReport(ctx context.Context, report *PentestReport) error
	ListPentestReportsByAuthor(ctx context.Context, author string) ([]PentestReport, error)
	FindingsVisibleTo(ctx context.Context, ids []int, userEmail string, isSheriff bool) ([]Ticket, error)
	GetPentestReport(ctx context.Context, id int) (*PentestReport, error)
	ListPentestReports(ctx context.Context) ([]PentestReport, error)
}

// PortalStore: what the owner's and the approver's links can do to a finding
type PortalStore interface {
	GetMagicBatch(ctx context.Context, token string) (*MagicBatch, error)
	TicketsByIDs(ctx context.Context, ids []int) ([]Ticket, error)
	SubmitPortalFix(ctx context.Context, ids []int, evidence, actor string) error
	RequestRiskException(ctx context.Context, ids []int, kind, rationale, actor string) error
	ReviewRiskRequest(ctx context.Context, ids []int, action, actor, comment string, days int) error
	// ReopenExpiredExceptions puts every accepted risk whose expiry has passed
	// back on the queue. It runs at boot and before every upload.
	ReopenExpiredExceptions(ctx context.Context) (int, error)
}
