package domain

import (
	"context"
	"net/http"
	"time"
)

// Store embeds all sub interfaces for Core
type Store interface {
	TicketStore
	IdentityStore
	IngestStore
	ConfigStore
	AnalyticsStore
	DraftStore
}

// TicketStore: Core CRUD and Workflow
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

// DraftStore: The Pentest Desk OSS, word docx
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
