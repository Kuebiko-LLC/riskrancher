// File: RiskRancher/pro/ui/pro_ui.go
package ui

import (
	"context"
	"embed"
	"html/template"
	"net/http"
	"strings"

	coreUI "github.com/Kuebiko-LLC/riskrancher/ui"
	"github.com/Kuebiko-LLC/riskrancher/pro/license"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// 🚨 UPDATED: Embed the full copied templates directory, components, and magic links
//
//go:embed templates/*.gohtml templates/components/*.gohtml templates/magic/*.gohtml static/*.js
var ProUIFS embed.FS

var ProTemplates map[string]*template.Template

func init() {
	ProTemplates = make(map[string]*template.Template)
	// We no longer load from CoreUIFS in init().
	// Everything is handled in InjectProTemplates where we have access to the license manager!
}

func InjectProTemplates(licenseManager *license.Manager, proStore storage.ProStoreInterface) {
	// 1. Create the dynamic FuncMap with PRO logic enabled
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"isProActive": func() bool {
			return licenseManager.IsEnterpriseActive()
		},
		"getProRules": func() any {
			rules, _ := proStore.GetRoutingRules(context.Background())
			return rules
		},
		"getCompanyName": func() string {
			if licenseManager.IsEnterpriseActive() {
				return licenseManager.GetCompanyName()
			}
			return ""
		},
		"getPendingRisks": func() any {
			tickets, _, _, _ := proStore.GetDashboardTickets(context.Background(), "Pending Risk Approval", "", "", "", "Sheriff", 50, 0)
			return tickets
		},
	}

	// 2. Load Pro-Specific Templates (Setup, Magic Links) directly from ProUIFS
	// Note: We skip template.Must on Setup just in case you accidentally deleted it during the copy over.
	setupTmpl, err := template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/setup.gohtml")
	if err == nil {
		ProTemplates["setup"] = setupTmpl
	}

	ProTemplates["wrangler"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/magic/wrangler.gohtml", "templates/components/*.gohtml"))
	ProTemplates["magistrate"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/magic/magistrate.gohtml", "templates/components/*.gohtml"))

	// 3. 🤠 THE TAKEOVER: Overwrite Core's Template Map with the Pro Monolith Files
	// We parse these entirely from ProUIFS, severing the dependency on coreUI.CoreUIFS
	coreUI.Pages["dashboard"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/dashboard.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["admin"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/admin.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["assets"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/assets.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["ingest"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/ingest.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["adapter_builder"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/adapter_builder.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["report_upload"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/report_upload.gohtml", "templates/components/*.gohtml"))
	coreUI.Pages["report_parser"] = template.Must(template.New("base").Funcs(funcMap).ParseFS(ProUIFS, "templates/base.gohtml", "templates/report_parser.gohtml", "templates/components/*.gohtml"))

	coreUI.Pages["login"] = template.Must(template.New("login").Funcs(funcMap).ParseFS(ProUIFS, "templates/login.gohtml"))
	coreUI.Pages["register"] = template.Must(template.New("register").Funcs(funcMap).ParseFS(ProUIFS, "templates/register.gohtml"))
}

// HandleLicenseSetupUI serves the OOBE activation page
func HandleLicenseSetupUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if tmpl, ok := ProTemplates["setup"]; ok {
			if err := tmpl.ExecuteTemplate(w, "base", nil); err != nil {
				http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
			}
		} else {
			http.Error(w, "Setup template not found. (Did you delete setup.gohtml during the copy?)", http.StatusInternalServerError)
		}
	}
}

// HandleMagicLinkUI serves the external exception pipeline view
func HandleMagicLinkUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// 🚀 Using "wrangler.gohtml" matching RiskRancher-main's expected execute name
		if err := ProTemplates["wrangler"].ExecuteTemplate(w, "wrangler.gohtml", nil); err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// HandleMagistrateUI serves the legal magic link view
func HandleMagistrateUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := ProTemplates["magistrate"].ExecuteTemplate(w, "magistrate.gohtml", nil); err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
