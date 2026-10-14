package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The System Logs tab's default choice is All, and All means no filter.
func TestAuditFeedAllMeansAll(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	ctx := context.Background()
	h.Store.LogAuditAction(ctx, "sheriff@rr.test", "PATCH", "/api/tickets/bulk", 200, "", "127.0.0.1")
	h.Store.LogAuditAction(ctx, "dana@rr.test", "POST", "/api/share/x/risk", 200, "", "127.0.0.1")
	for _, q := range []string{"?page=1&filter=All", "?page=1"} {
		rec := httptest.NewRecorder()
		h.HandleGetLogs(rec, httptest.NewRequest(http.MethodGet, "/api/admin/logs"+q, nil))
		var out struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK || out.Total != 2 {
			t.Fatalf("%s: want both rows, got %d %s", q, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.HandleGetLogs(rec, httptest.NewRequest(http.MethodGet, "/api/admin/logs?page=1&filter=/api/share", nil))
	var out struct {
		Total int `json:"total"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Total != 1 {
		t.Fatalf("a path filter narrows the feed, got %d", out.Total)
	}
}
