package storage

import (
	"context"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type ProStoreInterface interface {
	core.Store

	// --- Ticket workflow ---
	BulkUpdateStatusAndAssign(ctx context.Context, ticketIDs []int, status, assignee, comment, actor string) (string, error)
	RejectTicketFromWrangler(ctx context.Context, ticketIDs []int, reason, comment string) error

	// --- Rules engine ---
	CreateAutoTriageRule(ctx context.Context, rule *core.AutoTriageRule) error
	GetAutoTriageRules(ctx context.Context, workspaceID int) ([]core.AutoTriageRule, error)
	DeleteAutoTriageRule(ctx context.Context, ruleID int) error

	CreateSuppressionRule(ctx context.Context, rule *core.SuppressionRule) error
	CreateRoutingRule(ctx context.Context, rule *core.RoutingRule) error
	GetRoutingRules(ctx context.Context) ([]core.RoutingRule, error)
	DeleteRoutingRule(ctx context.Context, id int) error
	// --- Audit logging ---
	LogAuditAction(ctx context.Context, actor, action, resource string, statusCode int, errorDetails, ip string) error

	// Service accounts
	CreateAPIKey(ctx context.Context, key core.APIKey) (string, error)
	GetAPIKeyByHash(ctx context.Context, hash string) (*core.APIKey, error)

	// --- CISA KEV ---
	SyncCISACatalog(ctx context.Context, feed *core.CISAFeed) error

	// --- Engagements (a pentest owned by a Bounty Hunter) ---
	CreateEngagement(ctx context.Context, e *core.Engagement) (int, error)
	GetEngagement(ctx context.Context, id int) (*core.Engagement, error)
	ListEngagements(ctx context.Context) ([]core.Engagement, error)
	ListEngagementsByOwner(ctx context.Context, ownerEmail string) ([]core.Engagement, error)
	ReleaseEngagement(ctx context.Context, id int) error
	UpdateFindingDetails(ctx context.Context, ticketID int, d FindingDetails) error
	AddFindingsToEngagement(ctx context.Context, engagementID int, ticketIDs []int) error
	ListEngagementFindings(ctx context.Context, engagementID int) ([]core.Ticket, error)

	// --- Severity proposals (RangeHand <-> Bounty Hunter negotiation) ---
	ProposeSeverityChange(ctx context.Context, ticketID int, toSeverity, justification, proposedBy string) (*core.SeverityProposal, error)
	GetSeverityProposal(ctx context.Context, id int) (*core.SeverityProposal, error)
	ListProposalsForTicket(ctx context.Context, ticketID int) ([]core.SeverityProposal, error)
	AcceptSeverityProposal(ctx context.Context, proposalID int, actor string) error
	ContestSeverityProposal(ctx context.Context, proposalID int, actor, note string) error
	AdjudicateSeverityProposal(ctx context.Context, proposalID int, finalSeverity, actor, note string) error
	ListPendingProposalsForOwner(ctx context.Context, ownerEmail string) ([]core.SeverityProposal, error)
	ListContestedProposals(ctx context.Context) ([]core.SeverityProposal, error)
	EngagementOwnerForProposal(ctx context.Context, proposalID int) (string, error)

	// --- Finding templates (reusable finding library) ---
	CreateFindingTemplate(ctx context.Context, t *core.FindingTemplate) (int, error)
	GetFindingTemplate(ctx context.Context, id int) (*core.FindingTemplate, error)
	ListFindingTemplates(ctx context.Context) ([]core.FindingTemplate, error)
	UpdateFindingTemplate(ctx context.Context, t *core.FindingTemplate) error
	DeleteFindingTemplate(ctx context.Context, id int) error
	CreateFindingFromTemplate(ctx context.Context, templateID, engagementID int, asset, actor string) (int, error)

	// --- Evidence (screenshots attached to findings) ---
	AddEvidence(ctx context.Context, ev *core.Evidence, web, thumb []byte) (int, error)
	ListEvidenceForTicket(ctx context.Context, ticketID int) ([]core.Evidence, error)
	GetEvidenceMeta(ctx context.Context, id int) (*core.Evidence, error)
	GetEvidenceBlob(ctx context.Context, id int, thumb bool) ([]byte, string, error)
	DeleteEvidence(ctx context.Context, id int) error
	EngagementOwnerForTicket(ctx context.Context, ticketID int) (string, error)

	// --- Pentest reports (findings -> deliverable) ---
	CreatePentestReport(ctx context.Context, report *core.PentestReport) (int, error)
	UpdateReport(ctx context.Context, report *core.PentestReport) error
	ListPentestReportsByAuthor(ctx context.Context, author string) ([]core.PentestReport, error)
	FindingsVisibleTo(ctx context.Context, ids []int, userEmail string, isSheriff bool) ([]core.Ticket, error)
	GetPentestReport(ctx context.Context, id int) (*core.PentestReport, error)
	ListPentestReports(ctx context.Context) ([]core.PentestReport, error)

	GetProDashboardTickets(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]ProDashboardTicket, int, map[string]int, error)
}
