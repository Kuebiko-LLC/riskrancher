package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A key is ReadOnly or FullAdmin. Anything else is refused rather than
// silently granted full access.
func TestAPIKey_RejectsUnknownPermission(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	cookie := GetVIPCookie(h.Store)
	for body, want := range map[string]int{
		`{"name":"ci","permissions":"WriteOnly"}`: http.StatusBadRequest,
		`{"name":"ci","permissions":"root"}`:      http.StatusBadRequest,
		`{"name":"ci","permissions":"ReadOnly"}`:  http.StatusCreated,
		`{"name":"ci2"}`:                          http.StatusCreated,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys", strings.NewReader(body))
		req.AddCookie(cookie)
		req = req.WithContext(ctxWithUser(t, h, req))
		rec := httptest.NewRecorder()
		h.HandleCreateAPIKey(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: want %d got %d %s", body, want, rec.Code, rec.Body.String())
		}
	}
}
