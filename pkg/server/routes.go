package server

import (
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/adapters"
	"github.com/Kuebiko-LLC/riskrancher/pkg/admin"
	"github.com/Kuebiko-LLC/riskrancher/pkg/analytics"
	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/ingest"
	"github.com/Kuebiko-LLC/riskrancher/pkg/report"
	"github.com/Kuebiko-LLC/riskrancher/pkg/tickets"
	"github.com/Kuebiko-LLC/riskrancher/ui"
)

func RegisterRoutes(app *App) {

	authH := auth.NewHandler(app.Store)
	adminH := admin.NewHandler(app.Store)
	ticketH := tickets.NewHandler(app.Store)
	ingestH := ingest.NewHandler(app.Store)
	adapterH := adapters.NewHandler(app.Store)
	reportH := report.NewHandler(app.Store)
	analyticsH := analytics.NewHandler(app.Store)

	protected := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(http.HandlerFunc(h))
	}
	protectedUI := func(h http.HandlerFunc) http.Handler {
		return authH.RequireUIAuth(http.HandlerFunc(h))
	}
	sheriffOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(authH.RequireRole("Sheriff")(http.HandlerFunc(h)))
	}
	adminOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(authH.RequireAnyRole("Sheriff", "Wrangler")(http.HandlerFunc(h)))
	}

	// =========================================================
	// PUBLIC ROUTES
	// =========================================================
	app.Router.Handle("GET /login", ui.HandleLoginUI())
	app.Router.Handle("GET /register", ui.HandleRegisterUI())

	app.Router.HandleFunc("POST /api/auth/register", authH.HandleRegister)
	app.Router.HandleFunc("POST /api/auth/login", authH.HandleLogin)
	app.Router.HandleFunc("POST /api/auth/logout", authH.HandleLogout)

	// =========================================================
	// PROTECTED ROUTES
	// =========================================================
	app.Router.Handle("GET /api/wranglers", protected(adminH.HandleGetWranglers))
	app.Router.Handle("GET /", http.RedirectHandler("/dashboard", http.StatusSeeOther))
	app.Router.Handle("GET /dashboard", protectedUI(ui.HandleDashboard(app.Store)))

	// Core Tickets
	app.Router.Handle("GET /api/tickets", protected(ticketH.HandleGetTickets))
	app.Router.Handle("POST /api/tickets", protected(ticketH.HandleCreateTicket))
	app.Router.Handle("PATCH /api/tickets/{id}", protected(ticketH.HandleUpdateTicket))

	// Ingestion
	app.Router.Handle("POST /api/ingest", protected(ingestH.HandleIngest))
	app.Router.Handle("POST /api/ingest/csv", protected(ingestH.HandleCSVIngest))
	app.Router.Handle("POST /api/ingest/{name}", protected(adapterH.HandleAdapterIngest))

	// Adapters & Configuration
	app.Router.Handle("GET /api/adapters", protected(adapterH.HandleGetAdapters))
	app.Router.Handle("GET /api/config", protected(adminH.HandleGetConfig))
	app.Router.Handle("POST /api/adapters", protected(adapterH.HandleCreateAdapter))
	app.Router.Handle("DELETE /api/adapters/{id}", protected(adapterH.HandleDeleteAdapter))

	// Analytics
	app.Router.Handle("GET /api/analytics/summary", protected(analyticsH.HandleGetAnalyticsSummary))

	// Pentest Reports & Drafts (PDF PARSER - Free Lead Magnet!)
	app.Router.Handle("POST /api/reports/upload", protected(reportH.HandleUploadReport))
	app.Router.Handle("GET /api/reports/view/{id}", protected(reportH.HandleViewReport))
	app.Router.Handle("POST /api/drafts/report/{id}", protected(reportH.HandleSaveDraft))
	app.Router.Handle("GET /api/drafts/report/{id}", protected(reportH.HandleGetDrafts))
	app.Router.Handle("DELETE /api/drafts/{draft_id}", protected(reportH.HandleDeleteDraft))

	// =========================================================
	// SHERIFF & ADMIN ONLY
	// =========================================================

	app.Router.Handle("GET /admin", sheriffOnly(ui.HandleAdminDashboard(app.Store)))

	app.Router.Handle("GET /api/admin/export", sheriffOnly(adminH.HandleExportState))
	app.Router.Handle("GET /api/admin/check-updates", sheriffOnly(adminH.HandleCheckUpdates))
	app.Router.Handle("POST /api/admin/shutdown", sheriffOnly(adminH.HandleShutdown))

	app.Router.Handle("GET /api/admin/users", adminOnly(adminH.HandleGetUsers))
	app.Router.Handle("POST /api/admin/users", sheriffOnly(adminH.HandleCreateUser))
	app.Router.Handle("PATCH /api/admin/users/{id}/reset-password", sheriffOnly(adminH.HandleAdminResetPassword))
	app.Router.Handle("PATCH /api/admin/users/{id}/role", sheriffOnly(adminH.HandleUpdateUserRole))
	app.Router.Handle("DELETE /api/admin/users/{id}", sheriffOnly(adminH.HandleDeactivateUser))
	app.Router.Handle("GET /api/admin/logs", sheriffOnly(adminH.HandleGetLogs))

	app.Router.Handle("GET /static/", ui.StaticHandler())

	// =========================================================
	// UI EXTENSIONS
	// =========================================================

	app.Router.Handle("GET /ingest", protectedUI(ui.HandleIngestUI(app.Store)))
	app.Router.Handle("GET /admin/adapters/new", protectedUI(ui.HandleAdapterBuilderUI(app.Store)))

	// Word Docx Parser
	app.Router.Handle("GET /reports/parser/{id}", protectedUI(ui.HandleParserUI(app.Store)))
	app.Router.Handle("POST /api/reports/promote/{id}", protected(reportH.HandlePromoteDrafts))
	app.Router.Handle("GET /reports/upload", protectedUI(ui.HandlePentestUploadUI(app.Store)))
	app.Router.Handle("PUT /api/drafts/{id}", protected(reportH.HandleUpdateDraft))
	app.Router.Handle("POST /api/images/upload", protected(reportH.HandleImageUpload))
	app.Router.Handle("GET /uploads/", http.StripPrefix("/testdata/", http.FileServer(http.Dir("./data/testdata"))))
}
