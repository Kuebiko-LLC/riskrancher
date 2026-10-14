package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/server"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// The static mount serves scripts and nothing else: template source is not web-served.
func TestStaticMountServesScriptsOnly(t *testing.T) {
	db := datastore.InitDB(":memory:")
	defer db.Close()
	app := server.NewApp(storage.NewProSQLiteStore(db))
	server.RegisterRoutes(app)
	RegisterProRoutes(app)

	get := func(path string) int {
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if code := get("/static/pro/ingest.js"); code != http.StatusOK {
		t.Fatalf("ingest.js should be served at /static/pro/ingest.js, got %d", code)
	}
	if code := get("/static/pro/dashboard.js"); code != http.StatusOK {
		t.Fatalf("dashboard.js should be served at /static/pro/dashboard.js, got %d", code)
	}
	if code := get("/static/pro/templates/base.gohtml"); code != http.StatusNotFound {
		t.Fatalf("template source must not be web-served, got %d", code)
	}
	if code := get("/static/pro/static/dashboard.js"); code != http.StatusNotFound {
		t.Fatalf("the old double-static path should be gone, got %d", code)
	}
}
