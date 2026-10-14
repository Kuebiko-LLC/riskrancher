// Command rr is the RiskRancher binary: a self-hosted, air-gapped
// vulnerability-management platform in one process over one SQLite file.
// No network calls, no telemetry.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/server"
	coreui "github.com/Kuebiko-LLC/riskrancher/ui"

	proapi "github.com/Kuebiko-LLC/riskrancher/pro/api"
	prostorage "github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// Set at build time via -ldflags.
var (
	BuildVersion = "dev"
	BuildCommit  = "none"
)

func main() {
	coreui.SetVersionInfo(BuildVersion, BuildCommit)

	db := datastore.InitDB("./data/riskrancher.db")
	defer db.Close()

	prostorage.InjectProSchema(db)
	store := prostorage.NewProSQLiteStore(db)

	app := server.NewApp(store)

	server.RegisterRoutes(app)
	proapi.RegisterProRoutes(app)

	// The interceptor serves the dashboard and admin pages ahead of the mux.
	handler := proapi.ProUIInterceptor(app, app.Router)

	addr := os.Getenv("RR_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("🤠 RiskRancher running on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
