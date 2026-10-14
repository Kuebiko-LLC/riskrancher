// Command rr is the RiskRancher binary: a self-hosted, air-gapped
// vulnerability-management platform in one process over one SQLite file.
// No network calls, no telemetry.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

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
	if n, err := store.ReopenExpiredExceptions(context.Background()); err != nil {
		log.Printf("expiry sweep failed: %v", err)
	} else if n > 0 {
		log.Printf("expiry sweep: %d accepted risk(s) back on the queue", n)
	}

	app := server.NewApp(store)

	server.RegisterRoutes(app)

	addr := os.Getenv("RR_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{Addr: addr, Handler: app.Router}
	app.Shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
	log.Printf("🤠 RiskRancher running on http://localhost%s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Println("stopped")
}
