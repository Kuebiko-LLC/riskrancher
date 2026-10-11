// Command rr is the single RiskRancher binary: the open-source core
// vulnerability-management platform with every Pro and Auditor feature
// folded in and switched on. No license key, no paywall, no network calls.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/server"
	coreui "github.com/Kuebiko-LLC/riskrancher/ui"

	proapi "github.com/Kuebiko-LLC/riskrancher/pro/api"
	"github.com/Kuebiko-LLC/riskrancher/pro/license"
	"github.com/Kuebiko-LLC/riskrancher/pro/middleware"
	prostorage "github.com/Kuebiko-LLC/riskrancher/pro/storage"
	proui "github.com/Kuebiko-LLC/riskrancher/pro/ui"
)

// Set at build time via -ldflags.
var (
	BuildVersion = "dev"
	BuildCommit  = "none"
)

func main() {
	coreui.SetVersionInfo(BuildVersion, BuildCommit)

	// Core database + Pro schema, one SQLite file.
	db := datastore.InitDB("./data/riskrancher.db")
	defer db.Close()

	prostorage.InjectProSchema(db)
	store := prostorage.NewProSQLiteStore(db)

	app := server.NewApp(store)

	// Open edition: the license manager boots already unlocked, so every
	// Pro/Auditor feature is active. The verification code is kept (dormant)
	// so a commercial fork could re-gate it, but this binary never requires
	// a key. RR_PRO_LICENSE_KEY, if set, only labels the company banner.
	lm := license.NewManager(nil)
	if err := lm.LoadFromEnv(); err != nil {
		log.Printf("note: ignoring invalid RR_PRO_LICENSE_KEY (%v); all features stay unlocked", err)
	}
	if savedKey, _ := store.GetLicenseKey(context.Background()); savedKey != "" {
		_ = lm.Activate(savedKey)
	}

	proui.InjectProTemplates(lm, store)

	server.RegisterRoutes(app)
	proapi.RegisterProRoutes(app, lm)

	// These wrappers used to enforce the paywall; with the open-edition
	// manager they pass every request through and only handle Pro UI render.
	handler := proapi.ProUIInterceptor(app, lm, middleware.GlobalLicenseGate(lm, app.Router))

	log.Println("🤠 RiskRancher running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
