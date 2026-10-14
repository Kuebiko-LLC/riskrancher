package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The metrics page says plainly when no catalog is loaded, and how many
// CVEs it holds once one is, and the admin page carries a control to load it.
func TestAdminMetricsShowCatalogState(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("admin page: %d", rec.Code)
		}
		return rec.Body.String()
	}
	page := get()
	if !strings.Contains(page, "no catalog loaded") {
		t.Fatalf("with no catalog the KEV card must say so")
	}
	if !strings.Contains(page, `id="kevCatalogFile"`) || !strings.Contains(page, "loadKEVCatalog()") {
		t.Fatalf("the admin page must offer the catalog upload")
	}
	src, _ := fsReadUI("static/admin.js")
	if !strings.Contains(src, "/api/integrations/cisa/sync") || !strings.Contains(src, "cisa_catalog_file") {
		t.Fatalf("admin.js must post the file to the sync route as cisa_catalog_file")
	}
	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`), &feed)
	if err := app.Store.SyncCISACatalog(context.Background(), &feed); err != nil {
		t.Fatal(err)
	}
	if page = get(); !strings.Contains(page, "1 CVEs loaded") && !strings.Contains(page, "1 CVE loaded") {
		t.Fatalf("after a sync the KEV card must show the catalog size")
	}
}
