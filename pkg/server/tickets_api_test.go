package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The tickets API lists released findings only, pages, and carries the
// fields a script needs to act on a finding.
func TestTicketsAPI_HidesHeldFindingsAndPages(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	ctx := context.Background()
	for _, title := range []string{"one", "two", "three"} {
		tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: title, Severity: "High", Domain: "Vulnerability",
			TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
		if err := app.Store.CreateTicket(ctx, &tk); err != nil {
			t.Fatal(err)
		}
	}
	db := app.Store.(*datastore.SQLiteStore).DB
	if _, err := db.Exec(`UPDATE tickets SET released = 0 WHERE title = 'two'`); err != nil {
		t.Fatal(err)
	}
	list := func(q string) []map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/tickets"+q, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %q: %d %s", q, rec.Code, rec.Body.String())
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	all := list("")
	if len(all) != 2 {
		t.Fatalf("held finding must not be listed, got %d", len(all))
	}
	for _, row := range all {
		if row["title"] == "two" {
			t.Fatalf("held finding leaked")
		}
		if row["asset_identifier"] != "payments-api" || row["source"] != "Nessus" || row["remediation_due_date"] == nil {
			t.Fatalf("a row must carry asset, source and the clock: %v", row)
		}
	}
	if page := list("?limit=1&offset=1"); len(page) != 1 || page[0]["title"] != "three" {
		t.Fatalf("paging: %v", page)
	}
}
