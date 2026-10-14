package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The catalog endpoint says what is loaded and what it flags, not a
// hardcoded "active".
func TestGetCISACatalog_ReportsRealState(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()
	ctx := context.Background()

	read := func() map[string]any {
		rec := httptest.NewRecorder()
		a.HandleGetCISACatalog(rec, httptest.NewRequest(http.MethodGet, "/api/integrations/cisa", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d", rec.Code)
		}
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	if m := read(); m["loaded"].(float64) != 0 {
		t.Fatalf("nothing loaded yet: %v", m)
	}

	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-2021-44228 Log4Shell", Severity: "Critical", Domain: "Vulnerability"}
	if err := a.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"},{"cveID":"CVE-2014-0160","dateAdded":"2022-05-04"}]}`), &feed)
	if err := a.Store.SyncCISACatalog(ctx, &feed); err != nil {
		t.Fatal(err)
	}
	m := read()
	if m["loaded"].(float64) != 2 || m["flagged_open"].(float64) != 1 || m["last_added"] != "2022-05-04" {
		t.Fatalf("after a sync: %v", m)
	}
}
