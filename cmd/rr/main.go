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
	"github.com/Kuebiko-LLC/riskrancher/ui"
)

// Set at build time via -ldflags.
var (
	BuildVersion = "dev"
	BuildCommit  = "none"
)

func main() {
	ui.SetVersionInfo(BuildVersion, BuildCommit)

	db := datastore.InitDB("./data/riskrancher.db")
	defer db.Close()

	store := datastore.NewSQLiteStore(db)

	app := server.NewApp(store)

	server.RegisterRoutes(app)

	addr := os.Getenv("RR_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("🤠 RiskRancher running on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, app.Router))
}
