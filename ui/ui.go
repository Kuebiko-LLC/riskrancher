package ui

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/report"
)

//go:embed templates/* templates/components/* static/*
var CoreUIFS embed.FS

var (
	AppVersion = "dev"
	AppCommit  = "none"
)

var CoreTemplates *template.Template
var Pages map[string]*template.Template

// SetVersionInfo is called by main.go on startup to inject ldflags
func SetVersionInfo(version, commit string) {
	AppVersion = version
	AppCommit = commit
}

func init() {
	funcMap := template.FuncMap{
		"lower":          strings.ToLower,
		"isProActive":    func() bool { return false },
		"getCompanyName": func() string { return "" },
	}
	Pages = make(map[string]*template.Template)

	var err error

	CoreTemplates, err = template.New("").Funcs(funcMap).ParseFS(CoreUIFS, "templates/*.gohtml", "templates/components/*.gohtml")
	if err != nil && !strings.Contains(err.Error(), "pattern matches no files") {
		log.Printf("Warning: Failed to parse master core templates: %v", err)
	}

	dashTmpl := template.New("").Funcs(funcMap)
	dashTmpl, err = dashTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/dashboard.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse dashboard shell. Err: %v", err)
	}
	Pages["dashboard"] = dashTmpl

	adminTmpl := template.New("").Funcs(funcMap)
	adminTmpl, err = adminTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/admin.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse admin shell. Err: %v", err)
	}
	Pages["admin"] = adminTmpl

	Pages["login"], err = template.New("").Funcs(funcMap).ParseFS(CoreUIFS, "templates/login.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse login. Err: %v", err)
	}

	Pages["register"], err = template.New("").Funcs(funcMap).ParseFS(CoreUIFS, "templates/register.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse register. Err: %v", err)
	}

	Pages["assets"], err = template.New("").Funcs(funcMap).ParseFS(CoreUIFS, "templates/base.gohtml", "templates/assets.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse assets. Err: %v", err)
	}

	ingestTmpl := template.New("").Funcs(funcMap)
	ingestTmpl, err = ingestTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/ingest.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse ingest shell. Err: %v", err)
	}
	Pages["ingest"] = ingestTmpl

	adapterTmpl := template.New("").Funcs(funcMap)
	adapterTmpl, err = adapterTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/adapter_builder.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse adapter builder shell. Err: %v", err)
	}
	Pages["adapter_builder"] = adapterTmpl

	uploadTmpl := template.New("").Funcs(funcMap)
	uploadTmpl, err = uploadTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/report_upload.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse report upload template. Err: %v", err)
	}
	Pages["report_upload"] = uploadTmpl

	parserTmpl := template.New("").Funcs(funcMap)
	parserTmpl, err = parserTmpl.ParseFS(CoreUIFS, "templates/base.gohtml", "templates/report_parser.gohtml", "templates/components/*.gohtml")
	if err != nil {
		log.Fatalf("FATAL: Failed to parse report parser template. Err: %v", err)
	}
	Pages["report_parser"] = parserTmpl
}

func StaticHandler() http.Handler {
	staticFS, err := fs.Sub(CoreUIFS, "static")
	if err != nil {
		log.Fatal("Failed to load embedded static files:", err)
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
}

type PageData struct {
	Tickets           any
	CurrentTab        string
	CurrentFilter     string
	CurrentAsset      string
	ReturnedCount     int
	CountCritical     int
	CountOverdue      int
	CountMine         int
	CurrentPage       int
	TotalPages        int
	NextPage          int
	PrevPage          int
	CountVerification int
	HasNext           bool
	HasPrev           bool
	Version           string
	Commit            string
}

func HandleDashboard(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userIDVal := r.Context().Value(auth.UserIDKey)
		if userIDVal == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userID := userIDVal.(int)
		user, err := store.GetUserByID(r.Context(), userID)
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

		currentUserEmail := user.Email
		currentUserRole := user.GlobalRole

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

		pageStr := r.URL.Query().Get("page")
		page, _ := strconv.Atoi(pageStr)
		if page < 1 {
			page = 1
		}
		limit := 10 // assets per page; each asset group arrives whole
		offset := (page - 1) * limit

		tickets, totalRecords, metrics, err := store.GetDashboardTickets(
			r.Context(), statusFilter, filter, assetFilter, currentUserEmail, currentUserRole, limit, offset,
		)

		if err != nil {
			http.Error(w, "Database query error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		totalPages := int(math.Ceil(float64(totalRecords) / float64(limit)))
		if totalPages == 0 {
			totalPages = 1
		}

		data := PageData{
			Tickets:           tickets,
			CurrentTab:        tab,
			CurrentFilter:     filter,
			CurrentAsset:      assetFilter,
			ReturnedCount:     metrics["returned"],
			CountCritical:     metrics["critical"],
			CountOverdue:      metrics["overdue"],
			CountMine:         metrics["mine"],
			CountVerification: metrics["verification"],
			CurrentPage:       page,
			TotalPages:        totalPages,
			NextPage:          page + 1,
			PrevPage:          page - 1,
			HasNext:           page < totalPages,
			HasPrev:           page > 1,
			Version:           AppVersion,
			Commit:            AppCommit,
		}

		var buf bytes.Buffer
		if err := Pages["dashboard"].ExecuteTemplate(&buf, "base", data); err != nil {
			http.Error(w, "Template rendering error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
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

func HandleAdminDashboard(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, _ := store.GetAllUsers(r.Context())
		config, _ := store.GetAppConfig(r.Context())
		slas, _ := store.GetSLAPolicies(r.Context())
		adapters, _ := store.GetAdapters(r.Context())

		analytics, _ := store.GetSheriffAnalytics(r.Context())
		activityFeed, _ := store.GetGlobalActivityFeed(r.Context(), 15)
		syncLogs, _ := store.GetRecentSyncLogs(r.Context(), 10)

		data := map[string]any{
			"Users":     users,
			"Config":    config,
			"SLAs":      slas,
			"Adapters":  adapters,
			"Analytics": analytics,
			"Feed":      activityFeed,
			"SyncLogs":  syncLogs,
			"Version":   AppVersion,
			"Commit":    AppCommit,
		}

		var buf bytes.Buffer
		if err := Pages["admin"].ExecuteTemplate(&buf, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}
}

func HandleIngestUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		adapters, _ := store.GetAdapters(r.Context())
		data := map[string]any{
			"Adapters": adapters,
			"Version":  AppVersion,
			"Commit":   AppCommit,
		}

		if err := Pages["ingest"].ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleAdapterBuilderUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := map[string]any{
			"Filename": r.URL.Query().Get("filename"),
			"Version":  AppVersion,
			"Commit":   AppCommit,
		}
		if err := Pages["adapter_builder"].ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleParserUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		reportID := r.PathValue("id")

		filePath := filepath.Join(report.UploadDir, reportID)
		recorder := httptest.NewRecorder()
		report.ServeDOCXAsHTML(recorder, filePath)
		safeHTML := template.HTML(recorder.Body.String())

		data := map[string]any{
			"ReportID":     reportID,
			"RenderedHTML": safeHTML,
			"Version":      AppVersion,
			"Commit":       AppCommit,
		}

		if err := Pages["report_parser"].ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandlePentestUploadUI(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := map[string]any{
			"Version": AppVersion,
			"Commit":  AppCommit,
		}
		if err := Pages["report_upload"].ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
