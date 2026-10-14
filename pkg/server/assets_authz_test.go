package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The inventory and the rubric are the Sheriff's to change and to read.
func TestAssetAndRubricRoutesAreSheriffOnly(t *testing.T) {
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/assets"},
		{http.MethodPost, "/api/admin/assets/csv"},
		{http.MethodDelete, "/api/admin/assets/x"},
		{http.MethodGet, "/api/admin/rubric"},
		{http.MethodPut, "/api/admin/rubric"},
	}
	for _, role := range []string{"RangeHand", "Wrangler"} {
		app, cookie := appWithUser(t, role)
		for _, c := range calls {
			req := httptest.NewRequest(c.method, c.path, nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			app.Router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s %s: want 403, got %d", role, c.method, c.path, rec.Code)
			}
		}
	}
	app, cookie := appWithUser(t, "Sheriff")
	for _, path := range []string{"/api/admin/assets", "/api/admin/rubric"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Sheriff GET %s: %d", path, rec.Code)
		}
	}
}
