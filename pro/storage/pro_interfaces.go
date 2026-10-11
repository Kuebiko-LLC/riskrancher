// File: RiskRancher/pro/storage/pro_interfaces.go
package storage

import (
	"context"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

type ProStoreInterface interface {
	core.Store // Inherits all Free OSS methods!

	// --- 💎 PRO TICKET EXTENSIONS ---
	BulkUpdateStatusAndAssign(ctx context.Context, ticketIDs []int, status, assignee, comment, actor string) (string, error)
	RejectTicketFromWrangler(ctx context.Context, ticketIDs []int, reason, comment string) error

	// --- 💎 PRO ADMIN EXTENSIONS (Rules Engine) ---
	CreateAutoTriageRule(ctx context.Context, rule *proModels.AutoTriageRule) error
	GetAutoTriageRules(ctx context.Context, workspaceID int) ([]proModels.AutoTriageRule, error)
	DeleteAutoTriageRule(ctx context.Context, ruleID int) error

	CreateSuppressionRule(ctx context.Context, rule *proModels.SuppressionRule) error
	CreateRoutingRule(ctx context.Context, rule *proModels.RoutingRule) error
	GetRoutingRules(ctx context.Context) ([]proModels.RoutingRule, error)
	DeleteRoutingRule(ctx context.Context, id int) error
	// --- 💎 PRO COMPLIANCE & LOGGING ---
	LogAuditAction(ctx context.Context, actor, action, resource string, statusCode int, errorDetails, ip string) error

	// 🤠 PRO: Service Accounts
	CreateAPIKey(ctx context.Context, key proModels.APIKey) (string, error)
	GetAPIKeyByHash(ctx context.Context, hash string) (*proModels.APIKey, error)

	// --- 💎 PRO INTEGRATIONS (CISA) ---
	SyncCISACatalog(ctx context.Context, feed *proModels.CISAFeed) error

	// --- 💎 PRO OFFLINE LICENSE ---
	SaveLicenseKey(ctx context.Context, token string) error
	GetLicenseKey(ctx context.Context) (string, error)

	// --- 💎 ENGAGEMENTS (a pentest owned by a Bounty Hunter) ---
	CreateEngagement(ctx context.Context, e *proModels.Engagement) (int, error)
	GetEngagement(ctx context.Context, id int) (*proModels.Engagement, error)
	ListEngagements(ctx context.Context) ([]proModels.Engagement, error)
	ListEngagementsByOwner(ctx context.Context, ownerEmail string) ([]proModels.Engagement, error)
	ReleaseEngagement(ctx context.Context, id int) error
	AddFindingsToEngagement(ctx context.Context, engagementID int, ticketIDs []int) error
	ListEngagementFindings(ctx context.Context, engagementID int) ([]core.Ticket, error)

	// --- 💎 SEVERITY PROPOSALS (RangeHand <-> Bounty Hunter negotiation) ---
	ProposeSeverityChange(ctx context.Context, ticketID int, toSeverity, justification, proposedBy string) (*proModels.SeverityProposal, error)
	GetSeverityProposal(ctx context.Context, id int) (*proModels.SeverityProposal, error)
	ListProposalsForTicket(ctx context.Context, ticketID int) ([]proModels.SeverityProposal, error)
	AcceptSeverityProposal(ctx context.Context, proposalID int, actor string) error
	ContestSeverityProposal(ctx context.Context, proposalID int, actor, note string) error
	AdjudicateSeverityProposal(ctx context.Context, proposalID int, finalSeverity, actor, note string) error
	ListPendingProposalsForOwner(ctx context.Context, ownerEmail string) ([]proModels.SeverityProposal, error)
	ListContestedProposals(ctx context.Context) ([]proModels.SeverityProposal, error)
	EngagementOwnerForProposal(ctx context.Context, proposalID int) (string, error)

	// --- 💎 PRO PENTEST REPORTS (findings -> deliverable) ---
	CreatePentestReport(ctx context.Context, report *proModels.PentestReport) (int, error)
	UpdateReport(ctx context.Context, report *proModels.PentestReport) error
	GetPentestReport(ctx context.Context, id int) (*proModels.PentestReport, error)
	ListPentestReports(ctx context.Context) ([]proModels.PentestReport, error)

	GetProDashboardTickets(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]ProDashboardTicket, int, map[string]int, error)
}
