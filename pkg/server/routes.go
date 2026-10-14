package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	"github.com/Kuebiko-LLC/riskrancher/pkg/adapters"
	"github.com/Kuebiko-LLC/riskrancher/pkg/admin"
	"github.com/Kuebiko-LLC/riskrancher/pkg/analytics"
	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/ingest"
	"github.com/Kuebiko-LLC/riskrancher/pkg/report"
	"github.com/Kuebiko-LLC/riskrancher/pkg/tickets"
	"github.com/Kuebiko-LLC/riskrancher/ui"
)

// RegisterRoutes wires every route. Flow for API routes: auth, audit log, role, handler.
func RegisterRoutes(app *App) {
	authH := auth.NewHandler(app.Store)
	adminH := admin.NewHandler(app.Store)
	ticketH := tickets.NewHandler(app.Store)
	ingestH := ingest.NewHandler(app.Store)
	adapterH := adapters.NewHandler(app.Store)
	reportH := report.NewHandler(app.Store)
	analyticsH := analytics.NewHandler(app.Store)

	auditH := auth.AuditLogger(app.Store, slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	protected := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(http.HandlerFunc(h)))
	}
	protectedUI := func(h http.HandlerFunc) http.Handler {
		return authH.RequireUIAuth(http.HandlerFunc(h))
	}
	sheriffOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireRole("Sheriff")(http.HandlerFunc(h))))
	}
	adminOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireAnyRole("Sheriff", "Wrangler")(http.HandlerFunc(h))))
	}
	execOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireRole("Magistrate")(http.HandlerFunc(h))))
	}
	bountyHunter := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireAnyRole("Bounty Hunter", "Sheriff")(http.HandlerFunc(h))))
	}
	rangeHand := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireAnyRole("RangeHand", "Sheriff")(http.HandlerFunc(h))))
	}

	// Public
	app.Router.Handle("GET /login", ui.HandleLoginUI())
	app.Router.Handle("GET /register", ui.HandleRegisterUI())
	app.Router.HandleFunc("POST /api/auth/register", authH.HandleRegister)
	app.Router.HandleFunc("POST /api/auth/login", authH.HandleLogin)
	app.Router.HandleFunc("POST /api/auth/logout", authH.HandleLogout)
	app.Router.Handle("GET /static/", ui.StaticHandler())

	// Pages
	app.Router.Handle("GET /", http.RedirectHandler("/dashboard", http.StatusSeeOther))
	app.Router.Handle("GET /dashboard", protectedUI(ui.HandleDashboard(app.Store)))
	app.Router.Handle("GET /admin", sheriffOnly(ui.HandleAdminDashboard(app.Store)))
	app.Router.Handle("GET /ingest", protectedUI(ui.HandleIngestUI(app.Store)))
	app.Router.Handle("GET /admin/adapters/new", protectedUI(ui.HandleAdapterBuilderUI(app.Store)))
	app.Router.Handle("GET /reports/upload", protectedUI(ui.HandlePentestUploadUI(app.Store)))
	app.Router.Handle("GET /reports/parser/{id}", protectedUI(ui.HandleParserUI(app.Store)))
	app.Router.Handle("GET /engagements", bountyHunter(ui.HandleEngagementsUI(app.Store)))
	app.Router.Handle("GET /severity-reviews", rangeHand(ui.HandleSeverityReviewsUI(app.Store)))
	app.Router.Handle("GET /share/{token}", ui.HandleMagicLinkUI())
	app.Router.Handle("GET /review/{token}", ui.HandleMagistrateUI())

	// Tickets
	app.Router.Handle("GET /api/tickets", protected(ticketH.HandleGetTickets))
	app.Router.Handle("POST /api/tickets", protected(ticketH.HandleCreateTicket))
	app.Router.Handle("PATCH /api/tickets/{id}", protected(ticketH.HandleUpdateTicket))
	app.Router.Handle("PATCH /api/tickets/bulk", protected(ticketH.HandleBulkUpdate))
	app.Router.Handle("GET /api/wranglers", protected(adminH.HandleGetWranglers))

	// Portals (owner and risk approver)
	app.Router.Handle("GET /api/share/{token}", protected(ticketH.HandleMagicLink))
	app.Router.Handle("PATCH /api/share/{token}", protected(ticketH.HandleMagicLinkSubmit))
	app.Router.Handle("POST /api/share/{token}/reject", protected(ticketH.HandleWranglerReject))
	app.Router.Handle("POST /api/share/{token}/risk", protected(ticketH.HandleSubmitRiskRequest))
	app.Router.Handle("PATCH /api/risk/{token}/review", execOnly(ticketH.HandleMagistrateReview))

	// Ingest
	app.Router.Handle("POST /api/ingest", protected(ingestH.HandleIngest))
	app.Router.Handle("POST /api/ingest/csv", protected(ingestH.HandleCSVIngest))
	app.Router.Handle("POST /api/ingest/{name}", protected(adapterH.HandleAdapterIngest))

	// Adapters and configuration
	app.Router.Handle("GET /api/adapters", protected(adapterH.HandleGetAdapters))
	app.Router.Handle("POST /api/adapters", protected(adapterH.HandleCreateAdapter))
	app.Router.Handle("DELETE /api/adapters/{id}", protected(adapterH.HandleDeleteAdapter))
	app.Router.Handle("GET /api/config", protected(adminH.HandleGetConfig))
	app.Router.Handle("PUT /api/config", authH.RequireUIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			domain.AppConfig
			SLAs []domain.SLAPolicy `json:"slas"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if err := app.Store.UpdateAppConfig(r.Context(), payload.AppConfig); err != nil {
			http.Error(w, "Failed to update app config", http.StatusInternalServerError)
			return
		}
		if err := app.Store.UpdateSLAPolicies(r.Context(), payload.SLAs); err != nil {
			http.Error(w, "Failed to update SLAs", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})))

	// Analytics
	app.Router.Handle("GET /api/analytics/summary", protected(analyticsH.HandleGetAnalyticsSummary))
	app.Router.Handle("GET /api/analytics/executive", execOnly(adminH.HandleExecDashboardData))

	// Pentest report intake (upload, parse, draft, promote)
	app.Router.Handle("POST /api/reports/upload", protected(reportH.HandleUploadReport))
	app.Router.Handle("GET /api/reports/view/{id}", protected(reportH.HandleViewReport))
	app.Router.Handle("POST /api/drafts/report/{id}", protected(reportH.HandleSaveDraft))
	app.Router.Handle("GET /api/drafts/report/{id}", protected(reportH.HandleGetDrafts))
	app.Router.Handle("PUT /api/drafts/{id}", protected(reportH.HandleUpdateDraft))
	app.Router.Handle("DELETE /api/drafts/{draft_id}", protected(reportH.HandleDeleteDraft))
	app.Router.Handle("POST /api/reports/promote/{id}", protected(reportH.HandlePromoteDrafts))
	app.Router.Handle("POST /api/images/upload", protected(reportH.HandleImageUpload))
	app.Router.Handle("GET /uploads/", http.StripPrefix("/testdata/", http.FileServer(http.Dir("./data/testdata"))))

	// Engagements, finding templates, evidence, reports out
	app.Router.Handle("POST /api/engagements", bountyHunter(adminH.HandleCreateEngagement))
	app.Router.Handle("GET /api/engagements", protected(adminH.HandleListEngagements))
	app.Router.Handle("GET /api/engagements/{id}", protected(adminH.HandleGetEngagement))
	app.Router.Handle("POST /api/engagements/{id}/findings", bountyHunter(adminH.HandleAddEngagementFindings))
	app.Router.Handle("POST /api/engagements/{id}/release", bountyHunter(adminH.HandleReleaseEngagement))
	app.Router.Handle("POST /api/engagements/{id}/apply-template", bountyHunter(adminH.HandleApplyTemplate))
	app.Router.Handle("GET /api/finding-templates", bountyHunter(adminH.HandleListTemplates))
	app.Router.Handle("POST /api/finding-templates", bountyHunter(adminH.HandleCreateTemplate))
	app.Router.Handle("GET /api/finding-templates/{id}", bountyHunter(adminH.HandleGetTemplate))
	app.Router.Handle("PUT /api/finding-templates/{id}", bountyHunter(adminH.HandleUpdateTemplate))
	app.Router.Handle("DELETE /api/finding-templates/{id}", bountyHunter(adminH.HandleDeleteTemplate))
	app.Router.Handle("PUT /api/findings/{id}", bountyHunter(adminH.HandleUpdateFinding))
	app.Router.Handle("POST /api/findings/{id}/evidence", bountyHunter(adminH.HandleUploadEvidence))
	app.Router.Handle("GET /api/findings/{id}/evidence", bountyHunter(adminH.HandleListEvidence))
	app.Router.Handle("GET /api/evidence/{id}", bountyHunter(adminH.HandleGetEvidenceImage))
	app.Router.Handle("DELETE /api/evidence/{id}", bountyHunter(adminH.HandleDeleteEvidence))
	app.Router.Handle("POST /api/reports/branded", protected(adminH.HandleGenerateBrandedReport))
	app.Router.Handle("PUT /api/reports/branded/{id}", protected(adminH.HandleUpdateReport))
	app.Router.Handle("GET /api/reports/branded/{id}", protected(adminH.HandleGetPentestReport))
	app.Router.Handle("GET /api/reports/generated", protected(adminH.HandleListPentestReports))

	// Severity proposals
	app.Router.Handle("POST /api/findings/{id}/severity-proposal", rangeHand(adminH.HandleProposeSeverity))
	app.Router.Handle("POST /api/severity-proposals/{id}/accept", bountyHunter(adminH.HandleAcceptSeverityProposal))
	app.Router.Handle("POST /api/severity-proposals/{id}/contest", bountyHunter(adminH.HandleContestSeverityProposal))
	app.Router.Handle("POST /api/severity-proposals/{id}/adjudicate", sheriffOnly(adminH.HandleAdjudicateSeverityProposal))
	app.Router.Handle("GET /api/severity-proposals/mine", bountyHunter(adminH.HandleMyPendingProposals))
	app.Router.Handle("GET /api/severity-proposals/contested", sheriffOnly(adminH.HandleContestedProposals))

	// Sheriff: people, rules, integrations, logs, lifecycle
	app.Router.Handle("GET /api/admin/users", adminOnly(adminH.HandleGetUsers))
	app.Router.Handle("POST /api/admin/users", sheriffOnly(adminH.HandleCreateUser))
	app.Router.Handle("PATCH /api/admin/users/{id}/reset-password", sheriffOnly(adminH.HandleAdminResetPassword))
	app.Router.Handle("PATCH /api/admin/users/{id}/role", sheriffOnly(adminH.HandleUpdateUserRole))
	app.Router.Handle("DELETE /api/admin/users/{id}", sheriffOnly(adminH.HandleDeactivateUser))
	app.Router.Handle("GET /api/admin/routing", sheriffOnly(adminH.HandleGetRoutingRules))
	app.Router.Handle("POST /api/admin/routing", sheriffOnly(adminH.HandleCreateRoutingRule))
	app.Router.Handle("DELETE /api/admin/routing/{id}", sheriffOnly(adminH.HandleDeleteRoutingRule))
	app.Router.Handle("GET /api/admin/triage", sheriffOnly(adminH.HandleGetTriageRules))
	app.Router.Handle("POST /api/admin/triage", sheriffOnly(adminH.HandleCreateTriageRule))
	app.Router.Handle("DELETE /api/admin/triage/{id}", sheriffOnly(adminH.HandleDeleteTriageRule))
	app.Router.Handle("GET /api/admin/suppression", sheriffOnly(adminH.HandleGetSuppressionRules))
	app.Router.Handle("POST /api/admin/suppression", sheriffOnly(adminH.HandleCreateSuppressionRule))
	app.Router.Handle("DELETE /api/admin/suppression/{id}", sheriffOnly(adminH.HandleDeleteSuppressionRule))
	app.Router.Handle("GET /api/admin/apikeys", sheriffOnly(adminH.HandleGetAPIKeys))
	app.Router.Handle("POST /api/admin/apikeys", sheriffOnly(adminH.HandleCreateAPIKey))
	app.Router.Handle("DELETE /api/admin/apikeys/{id}", sheriffOnly(adminH.HandleRevokeAPIKey))
	app.Router.Handle("POST /api/integrations/cisa/sync", sheriffOnly(adminH.HandleSyncCISAKEV))
	app.Router.Handle("GET /api/integrations/cisa", protected(adminH.HandleGetCISACatalog))
	app.Router.Handle("GET /api/admin/logs", sheriffOnly(adminH.HandleGetLogs))
	app.Router.Handle("GET /api/admin/export", sheriffOnly(adminH.HandleExportState))
	app.Router.Handle("GET /api/admin/check-updates", sheriffOnly(adminH.HandleCheckUpdates))
	app.Router.Handle("POST /api/admin/shutdown", sheriffOnly(adminH.HandleShutdown))
}
