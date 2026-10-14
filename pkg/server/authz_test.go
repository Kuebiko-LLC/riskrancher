package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

func appWithUser(t *testing.T, role string) (*App, *http.Cookie) {
	t.Helper()
	db := datastore.InitDB(":memory:")
	t.Cleanup(func() { db.Close() })
	app := NewApp(datastore.NewSQLiteStore(db))
	RegisterRoutes(app)
	u, err := app.Store.CreateUser(context.Background(), role+"@rr.test", role, "hash", role)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.CreateSession(context.Background(), "tok-"+role, u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return app, &http.Cookie{Name: "session_token", Value: "tok-" + role}
}

// Only the Sheriff can rewrite the SLA matrix and app configuration.
func TestConfigWriteIsSheriffOnly(t *testing.T) {
	body := `{"timezone":"UTC","business_start":9,"business_end":17,"default_extension_days":30,"slas":[]}`
	for role, want := range map[string]int{"RangeHand": http.StatusForbidden, "Wrangler": http.StatusForbidden, "Sheriff": http.StatusOK} {
		app, cookie := appWithUser(t, role)
		req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s writing config: want %d, got %d", role, want, rec.Code)
		}
	}
}

// Uploaded report images are served back at the URL the upload handler hands out.
func TestUploadsRouteServesFiles(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	dir := filepath.Join("data", "testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "probe-" + t.Name() + ".txt"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	req := httptest.NewRequest(http.MethodGet, "/testdata/"+name, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("uploaded file should be served, got %d %q", rec.Code, rec.Body.String())
	}
}

// Report images are evidence from a client's pentest: no session, no file.
func TestUploadsRouteRequiresAuth(t *testing.T) {
	app, _ := appWithUser(t, "Sheriff")
	req := httptest.NewRequest(http.MethodGet, "/testdata/images/anything.png", nil)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusNotFound {
		t.Fatalf("without a session the uploads route must refuse, got %d", rec.Code)
	}
}
