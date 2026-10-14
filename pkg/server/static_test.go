package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

// The static mount serves scripts and styles and nothing else: template source is not web-served.
func TestStaticMountServesAssetsOnly(t *testing.T) {
	db := datastore.InitDB(":memory:")
	defer db.Close()
	app := NewApp(datastore.NewSQLiteStore(db))
	RegisterRoutes(app)

	get := func(path string) int {
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	for _, p := range []string{"/static/dashboard.js", "/static/magic.js", "/static/ingest.js", "/static/auth.js", "/static/style.css"} {
		if code := get(p); code != http.StatusOK {
			t.Fatalf("%s should be served, got %d", p, code)
		}
	}
	if code := get("/static/templates/base.gohtml"); code != http.StatusNotFound {
		t.Fatalf("template source must not be web-served, got %d", code)
	}
}
