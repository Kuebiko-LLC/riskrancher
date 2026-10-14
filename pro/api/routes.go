package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	models "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	core "github.com/Kuebiko-LLC/riskrancher/pkg/server"
	coreUI "github.com/Kuebiko-LLC/riskrancher/ui"

	proAdmin "github.com/Kuebiko-LLC/riskrancher/pro/admin"
	"github.com/Kuebiko-LLC/riskrancher/pro/middleware"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
	proTickets "github.com/Kuebiko-LLC/riskrancher/pro/tickets"
	proUI "github.com/Kuebiko-LLC/riskrancher/pro/ui"
)

func ProUIInterceptor(app *core.App, next http.Handler) http.Handler {
	authH := auth.NewHandler(app.Store)

	// The admin handler is used by the interceptor
	proAdminH := proAdmin.NewProHandler(app.Store)

	sheriffOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(authH.RequireRole("Sheriff")(http.HandlerFunc(h)))
	}

	// 🚀 NEW: Wrap the logs handler with the sheriff-only auth check
	proLogsAPI := sheriffOnly(proAdminH.HandleGetLogs)

	// ==========================================
	// 🤠 1. THE ADMIN DASHBOARD INTERCEPTOR
	// ==========================================
	proAdminUI := sheriffOnly(func(w http.ResponseWriter, r *http.Request) {
		users, _ := app.Store.GetAllUsers(r.Context())
		config, _ := app.Store.GetAppConfig(r.Context())
		slas, _ := app.Store.GetSLAPolicies(r.Context())
		adapters, _ := app.Store.GetAdapters(r.Context())
		analytics, _ := app.Store.GetSheriffAnalytics(r.Context())
		activityFeed, _ := app.Store.GetGlobalActivityFeed(r.Context(), 15)
		syncLogs, _ := app.Store.GetRecentSyncLogs(r.Context(), 10)

		proStore, ok := app.Store.(storage.ProStoreInterface)
		if !ok {
			log.Println("🚨 CRITICAL: Store is not a ProStoreInterface!")
		}
		// 🚀 FETCH THE REAL RULES!
		rules, _ := proStore.GetRoutingRules(r.Context())
		riskTickets, _, _, _ := proStore.GetProDashboardTickets(r.Context(), "Pending Risk Approval", "", "", "", "Sheriff", 50, 0)
		unreadRiskCount := 0
		for _, t := range riskTickets {
			if t.OwnerViewedAt == nil {
				unreadRiskCount++
			}
		}

		data := map[string]any{
			"Users":            users,
			"Config":           config,
			"SLAs":             slas,
			"Adapters":         adapters,
			"Analytics":        analytics,
			"Feed":             activityFeed,
			"SyncLogs":         syncLogs,
			"RiskRequests":     riskTickets,
			"PendingRiskCount": unreadRiskCount,
			"Rules":            rules,
			"Version":          coreUI.AppVersion,
			"Commit":           coreUI.AppCommit,
		}

		var buf bytes.Buffer
		if err := coreUI.Pages["admin"].ExecuteTemplate(&buf, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	})

	// ==========================================
	// 🚀 2. THE MAIN DASHBOARD INTERCEPTOR
	// ==========================================
	proDashboardUI := authH.RequireUIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDVal := r.Context().Value(auth.UserIDKey)
		if userIDVal == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userID := userIDVal.(int)
		user, err := app.Store.GetUserByID(r.Context(), userID)
		if err != nil || user.GlobalRole == "Sheriff" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if user.GlobalRole == "Bounty Hunter" {
			http.Redirect(w, r, "/engagements", http.StatusSeeOther)
			return
		}

		tab := r.URL.Query().Get("tab")
		if tab == "" {
			tab = "holding_pen"
		}

		statusFilter := tab
		if tab == "holding_pen" {
			statusFilter = "Waiting to be Triaged"
		} else if tab == "chute" {
			statusFilter = "Assigned Out"
		} else if tab == "verification" {
			statusFilter = "Pending Verification"
		}

		filter := r.URL.Query().Get("filter")
		assetFilter := r.URL.Query().Get("asset")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		limit := 10 // assets per page; each asset group arrives whole
		offset := (page - 1) * limit

		proStore, ok := app.Store.(storage.ProStoreInterface)
		if !ok {
			http.Error(w, "Pro store not configured", http.StatusInternalServerError)
			return
		}

		// 🚀 FETCH ENTERPRISE TICKETS: This attaches the MagicTokens!
		tickets, totalRecords, metrics, err := proStore.GetProDashboardTickets(r.Context(), statusFilter, filter, assetFilter, user.Email, user.GlobalRole, limit, offset)
		if err != nil {
			http.Error(w, "DB Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		totalPages := totalRecords / limit
		if totalRecords%limit != 0 {
			totalPages++
		}
		if totalPages == 0 {
			totalPages = 1
		}

		data := map[string]any{
			"Tickets":           tickets, // This is now []ProDashboardTicket!
			"CurrentTab":        tab,
			"CurrentFilter":     filter,
			"CurrentAsset":      assetFilter,
			"ReturnedCount":     metrics["returned"],
			"CountCritical":     metrics["critical"],
			"CountOverdue":      metrics["overdue"],
			"CountMine":         metrics["mine"],
			"CountVerification": metrics["verification"],
			"CurrentPage":       page,
			"TotalPages":        totalPages,
			"NextPage":          page + 1,
			"PrevPage":          page - 1,
			"HasNext":           page < totalPages,
			"HasPrev":           page > 1,
		}

		var buf bytes.Buffer
		if err := coreUI.Pages["dashboard"].ExecuteTemplate(&buf, "base", data); err != nil {
			log.Printf("🚨 Dashboard template render failed: %v", err)
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}))

	// ==========================================
	// 🚦 3. THE ROUTER GATE
	// ==========================================
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")

		// Serve the rendered pages ahead of the mux.
		if r.Method == "GET" {
			if path == "/admin" {
				proAdminUI.ServeHTTP(w, r)
				return
			}
			if path == "/dashboard" {
				proDashboardUI.ServeHTTP(w, r)
				return
			}
			// The logs API is served here, ahead of the mux
			if path == "/api/admin/logs" {
				proLogsAPI.ServeHTTP(w, r)
				return
			}
		}

		// Otherwise, pass through to the mux
		next.ServeHTTP(w, r)
	})
}

func RegisterProRoutes(app *core.App) {
	proStore := app.Store.(storage.ProStoreInterface)

	proUI.InjectProTemplates(proStore)

	authH := auth.NewHandler(app.Store)
	proTicketH := proTickets.NewProHandler(app.Store)
	proAdminH := proAdmin.NewProHandler(app.Store)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auditH := middleware.AuditLogger(proStore, logger)

	// Flow: Auth Check -> Audit Logger -> Role Check -> Handler
	protected := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(http.HandlerFunc(h)))
	}
	sheriffOnly := func(h http.HandlerFunc) http.Handler {
		return authH.RequireAuth(auditH(authH.RequireRole("Sheriff")(http.HandlerFunc(h))))
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

	// ==========================================
	// ⚖️ SEVERITY PROPOSALS (RangeHand <-> Bounty Hunter <-> Sheriff)
	// ==========================================
	app.Router.Handle("GET /severity-reviews", rangeHand(proUI.HandleSeverityReviewsUI(app.Store)))
	app.Router.Handle("POST /api/findings/{id}/severity-proposal", rangeHand(proAdminH.HandleProposeSeverity))
	app.Router.Handle("POST /api/severity-proposals/{id}/accept", bountyHunter(proAdminH.HandleAcceptSeverityProposal))
	app.Router.Handle("POST /api/severity-proposals/{id}/contest", bountyHunter(proAdminH.HandleContestSeverityProposal))
	app.Router.Handle("POST /api/severity-proposals/{id}/adjudicate", sheriffOnly(proAdminH.HandleAdjudicateSeverityProposal))
	app.Router.Handle("GET /api/severity-proposals/mine", bountyHunter(proAdminH.HandleMyPendingProposals))
	app.Router.Handle("GET /api/severity-proposals/contested", sheriffOnly(proAdminH.HandleContestedProposals))

	// ==========================================
	// 🤠 ENGAGEMENTS (Bounty Hunter pentests)
	// ==========================================
	app.Router.Handle("GET /engagements", bountyHunter(proUI.HandleEngagementsUI(app.Store)))
	app.Router.Handle("POST /api/engagements", bountyHunter(proAdminH.HandleCreateEngagement))
	app.Router.Handle("GET /api/engagements", protected(proAdminH.HandleListEngagements))
	app.Router.Handle("GET /api/engagements/{id}", protected(proAdminH.HandleGetEngagement))
	app.Router.Handle("POST /api/engagements/{id}/findings", bountyHunter(proAdminH.HandleAddEngagementFindings))
	app.Router.Handle("POST /api/engagements/{id}/release", bountyHunter(proAdminH.HandleReleaseEngagement))

	// Finding templates (reusable library)
	app.Router.Handle("GET /api/finding-templates", bountyHunter(proAdminH.HandleListTemplates))
	app.Router.Handle("POST /api/finding-templates", bountyHunter(proAdminH.HandleCreateTemplate))
	app.Router.Handle("GET /api/finding-templates/{id}", bountyHunter(proAdminH.HandleGetTemplate))
	app.Router.Handle("PUT /api/finding-templates/{id}", bountyHunter(proAdminH.HandleUpdateTemplate))
	app.Router.Handle("DELETE /api/finding-templates/{id}", bountyHunter(proAdminH.HandleDeleteTemplate))
	app.Router.Handle("POST /api/engagements/{id}/apply-template", bountyHunter(proAdminH.HandleApplyTemplate))

	app.Router.Handle("PUT /api/findings/{id}", bountyHunter(proAdminH.HandleUpdateFinding))

	// Evidence (screenshots on findings)
	app.Router.Handle("POST /api/findings/{id}/evidence", bountyHunter(proAdminH.HandleUploadEvidence))
	app.Router.Handle("GET /api/findings/{id}/evidence", bountyHunter(proAdminH.HandleListEvidence))
	app.Router.Handle("GET /api/evidence/{id}", bountyHunter(proAdminH.HandleGetEvidenceImage))
	app.Router.Handle("DELETE /api/evidence/{id}", bountyHunter(proAdminH.HandleDeleteEvidence))

	// ==========================================
	// Overrides of base routes
	// ==========================================
	app.Router.Handle("PUT /api/config", authH.RequireUIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			models.AppConfig
			SLAs []models.SLAPolicy `json:"slas"`
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

	// ==========================================
	// Exception pipeline and magic links
	// ==========================================
	// The IT View (Wrangler)
	app.Router.Handle("GET /share/{token}", proUI.HandleMagicLinkUI())
	app.Router.Handle("GET /api/share/{token}", protected(proTicketH.HandleMagicLink))
	app.Router.Handle("PATCH /api/share/{token}", protected(proTicketH.HandleMagicLinkSubmit))
	app.Router.Handle("POST /api/share/{token}/reject", protected(proTicketH.HandleWranglerReject))
	app.Router.Handle("POST /api/share/{token}/risk", protected(proTicketH.HandleSubmitRiskRequest))

	app.Router.Handle("GET /review/{token}", proUI.HandleMagistrateUI())
	app.Router.Handle("PATCH /api/risk/{token}/review", execOnly(proTicketH.HandleMagistrateReview))

	// ==========================================
	// Bulk actions
	// ==========================================
	app.Router.Handle("PATCH /api/tickets/bulk", protected(proTicketH.HandleBulkUpdate))

	// ==========================================
	// Admin settings (Sheriff only)
	// ==========================================

	app.Router.Handle("GET /api/admin/routing", sheriffOnly(proAdminH.HandleGetRoutingRules))
	app.Router.Handle("POST /api/admin/routing", sheriffOnly(proAdminH.HandleCreateRoutingRule))
	app.Router.Handle("DELETE /api/admin/routing/{id}", sheriffOnly(proAdminH.HandleDeleteRoutingRule))

	app.Router.Handle("GET /api/admin/triage", sheriffOnly(proAdminH.HandleGetTriageRules))
	app.Router.Handle("POST /api/admin/triage", sheriffOnly(proAdminH.HandleCreateTriageRule))
	app.Router.Handle("DELETE /api/admin/triage/{id}", sheriffOnly(proAdminH.HandleDeleteTriageRule))

	app.Router.Handle("GET /api/admin/suppression", sheriffOnly(proAdminH.HandleGetSuppressionRules))
	app.Router.Handle("POST /api/admin/suppression", sheriffOnly(proAdminH.HandleCreateSuppressionRule))
	app.Router.Handle("DELETE /api/admin/suppression/{id}", sheriffOnly(proAdminH.HandleDeleteSuppressionRule))

	app.Router.Handle("GET /api/admin/apikeys", sheriffOnly(proAdminH.HandleGetAPIKeys))
	app.Router.Handle("POST /api/admin/apikeys", sheriffOnly(proAdminH.HandleCreateAPIKey))
	app.Router.Handle("DELETE /api/admin/apikeys/{id}", sheriffOnly(proAdminH.HandleRevokeAPIKey))

	// ==========================================
	// CISA KEV and data integrations
	// ==========================================
	app.Router.Handle("POST /api/integrations/cisa/sync", sheriffOnly(proAdminH.HandleSyncCISAKEV))
	app.Router.Handle("GET /api/integrations/cisa", protected(proAdminH.HandleGetCISACatalog))

	// ==========================================
	// Reporting
	// ==========================================
	app.Router.Handle("POST /api/reports/branded", protected(proAdminH.HandleGenerateBrandedReport))
	app.Router.Handle("PUT /api/reports/branded/{id}", protected(proAdminH.HandleUpdateReport))
	app.Router.Handle("GET /api/reports/branded/{id}", protected(proAdminH.HandleGetPentestReport))
	app.Router.Handle("GET /api/reports/generated", protected(proAdminH.HandleListPentestReports))

	// ==========================================
	// Executive dashboard
	// ==========================================
	app.Router.Handle("GET /api/analytics/executive", execOnly(proAdminH.HandleExecDashboardData))

	// ==========================================
	// STATIC ASSETS (JS/CSS)
	// ==========================================
	// Scripts only: the embedded templates are not web-served.
	staticFS, err := fs.Sub(proUI.ProUIFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}
	app.Router.Handle("GET /static/pro/", http.StripPrefix("/static/pro/", http.FileServer(http.FS(staticFS))))
}
