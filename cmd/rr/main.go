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
	// Global middleware (outermost runs first): security headers, then a request-body
	// limit, then cross-origin protection (CSRF) around the router. CSRF rejects a
	// cross-site browser POST via Sec-Fetch-Site but allows same-origin requests and
	// non-browser clients (scanners sending a Bearer key, which carry no Origin), so
	// the UI, the portals and API ingest all keep working (RR-L6).
	csrf := http.NewCrossOriginProtection()
	handler := server.SecurityHeaders(server.LimitBody(csrf.Handler(app.Router)))
	srv := &http.Server{Addr: addr, Handler: handler}
	app.Shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
	log.Printf("RiskRancher running on http://localhost%s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Println("stopped")
}
