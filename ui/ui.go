package ui

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/report"
)

//go:embed templates/*.gohtml templates/components/*.gohtml templates/magic/*.gohtml static/*
var UIFS embed.FS

var (
	AppVersion = "dev"
	AppCommit  = "none"
)

// Pages are the server-rendered pages, keyed by name. Portals are the two
// account-less views reached by magic link.
var (
	Pages   map[string]*template.Template
	Portals map[string]*template.Template
)

// SetVersionInfo is called by main on startup to inject ldflags.
func SetVersionInfo(version, commit string) {
	AppVersion = version
	AppCommit = commit
}

func init() {
	funcMap := template.FuncMap{"lower": strings.ToLower}
	page := func(file string) *template.Template {
		return template.Must(template.New("base").Funcs(funcMap).ParseFS(UIFS, "templates/base.gohtml", "templates/"+file, "templates/components/*.gohtml"))
	}
	Pages = map[string]*template.Template{
		"dashboard":        page("dashboard.gohtml"),
		"admin":            page("admin.gohtml"),
		"ingest":           page("ingest.gohtml"),
		"adapter_builder":  page("adapter_builder.gohtml"),
		"report_upload":    page("report_upload.gohtml"),
		"report_parser":    page("report_parser.gohtml"),
		"engagements":      page("engagements.gohtml"),
		"severity_reviews": page("severity_reviews.gohtml"),
		"login":            template.Must(template.New("login").Funcs(funcMap).ParseFS(UIFS, "templates/login.gohtml")),
		"register":         template.Must(template.New("register").Funcs(funcMap).ParseFS(UIFS, "templates/register.gohtml")),
	}
	Portals = map[string]*template.Template{
		"wrangler":   template.Must(template.New("base").Funcs(funcMap).ParseFS(UIFS, "templates/magic/wrangler.gohtml", "templates/components/*.gohtml")),
		"magistrate": template.Must(template.New("base").Funcs(funcMap).ParseFS(UIFS, "templates/magic/magistrate.gohtml", "templates/components/*.gohtml")),
	}
}

// StaticHandler serves scripts and styles only; templates are never web-served.
func StaticHandler() http.Handler {
	staticFS, err := fs.Sub(UIFS, "static")
	if err != nil {
		log.Fatal("Failed to load embedded static files:", err)
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
}

func render(w http.ResponseWriter, page string, data any) {
	var buf bytes.Buffer
	if err := Pages[page].ExecuteTemplate(&buf, "base", data); err != nil {
		http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// HandleDashboard is the triage queue: asset groups, a page at a time, with the
// portal token on each finding.
func HandleDashboard(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := r.Context().Value(auth.UserIDKey).(int)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := store.GetUserByID(r.Context(), id)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if user.GlobalRole == "Sheriff" {
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
		switch tab {
		case "holding_pen":
			statusFilter = "Waiting to be Triaged"
		case "chute":
			statusFilter = "Assigned Out"
		case "verification":
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

		tickets, totalRecords, metrics, err := store.GetDashboardTicketsWithPortals(r.Context(), statusFilter, filter, assetFilter, user.Email, user.GlobalRole, limit, offset)
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
		render(w, "dashboard", map[string]any{
			"Tickets":           tickets,
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
		})
	}
}

// HandleAdminDashboard is the Sheriff's office: people, policy, rules, metrics, and the risk queue.
func HandleAdminDashboard(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, _ := store.GetAllUsers(r.Context())
		config, _ := store.GetAppConfig(r.Context())
		slas, _ := store.GetSLAPolicies(r.Context())
		adapterList, _ := store.GetAdapters(r.Context())
		metrics, _ := store.GetSheriffAnalytics(r.Context())
		activityFeed, _ := store.GetGlobalActivityFeed(r.Context(), 15)
		syncLogs, _ := store.GetRecentSyncLogs(r.Context(), 10)
		rules, _ := store.GetRoutingRules(r.Context())
		riskTickets, _, _, _ := store.GetDashboardTicketsWithPortals(r.Context(), "Pending Risk Approval", "", "", "", "Sheriff", 50, 0)
		render(w, "admin", map[string]any{
			"Users":            users,
			"Config":           config,
			"SLAs":             slas,
			"Adapters":         adapterList,
			"Analytics":        metrics,
			"Feed":             activityFeed,
			"SyncLogs":         syncLogs,
			"RiskRequests":     riskTickets,
			"PendingRiskCount": len(riskTickets),
			"Rules":            rules,
			"Version":          AppVersion,
			"Commit":           AppCommit,
		})
	}
}

func HandleLoginUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := Pages["login"].ExecuteTemplate(w, "login", nil); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleRegisterUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := Pages["register"].ExecuteTemplate(w, "register", nil); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleIngestUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapterList, _ := store.GetAdapters(r.Context())
		render(w, "ingest", map[string]any{"Adapters": adapterList, "Version": AppVersion, "Commit": AppCommit})
	}
}

func HandleAdapterBuilderUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "adapter_builder", map[string]any{"Filename": r.URL.Query().Get("filename"), "Version": AppVersion, "Commit": AppCommit})
	}
}

func HandleParserUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reportID := r.PathValue("id")
		recorder := httptest.NewRecorder()
		report.ServeDOCXAsHTML(recorder, filepath.Join(report.UploadDir, reportID))
		render(w, "report_parser", map[string]any{"ReportID": reportID, "RenderedHTML": template.HTML(recorder.Body.String()), "Version": AppVersion, "Commit": AppCommit})
	}
}

func HandlePentestUploadUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "report_upload", map[string]any{"Version": AppVersion, "Commit": AppCommit})
	}
}

// userPage serves a script-driven page that only needs the signed-in user's
// identity as server data; the page talks to the JSON APIs.
func userPage(store domain.Store, page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := r.Context().Value(auth.UserIDKey).(int)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := store.GetUserByID(r.Context(), id)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		render(w, page, map[string]any{"Email": u.Email, "Role": u.GlobalRole})
	}
}

// HandleEngagementsUI serves the Bounty Hunter workspace (engagements and the report builder).
func HandleEngagementsUI(store domain.Store) http.HandlerFunc { return userPage(store, "engagements") }

// HandleSeverityReviewsUI serves the severity-proposal review page.
func HandleSeverityReviewsUI(store domain.Store) http.HandlerFunc {
	return userPage(store, "severity_reviews")
}

// HandleMagicLinkUI serves the owner's portal (fix, request more time, request an exception).
func HandleMagicLinkUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := Portals["wrangler"].ExecuteTemplate(w, "wrangler.gohtml", nil); err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// HandleMagistrateUI serves the risk approver's portal.
func HandleMagistrateUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := Portals["magistrate"].ExecuteTemplate(w, "magistrate.gohtml", nil); err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
