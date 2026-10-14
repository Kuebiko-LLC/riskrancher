package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The audit trail names the signed-in user, whatever the page put in the body.
func TestBulkActorComesFromSession(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 actor", Severity: "High", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := app.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/tickets/bulk", `{"ticket_ids":[` + strconv.Itoa(tk.ID) + `],"status":"Triaged","comment":"looked at it","actor":"Mallory"}`},
		{http.MethodPatch, "/api/tickets/" + strconv.Itoa(tk.ID), `{"severity":"Medium","comment":"downgraded","actor":"Mallory"}`},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	var actors []string
	db := app.Store.(*datastore.SQLiteStore).DB
	r, err := db.Query(`SELECT DISTINCT actor FROM ticket_activity WHERE ticket_id = ?`, tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var a string
		r.Scan(&a)
		actors = append(actors, a)
	}
	r.Close()
	got, _ := app.Store.GetTicketByID(ctx, tk.ID)
	if strings.Contains(strings.Join(actors, ","), "Mallory") || !strings.Contains(strings.Join(actors, ","), "RangeHand@rr.test") || strings.Contains(got.LatestComment, "Mallory") {
		t.Fatalf("actor must be the session user: activity actors=%v comment=%q", actors, got.LatestComment)
	}
}

// Adapters shape what every upload becomes; only the security team edits them.
func TestAdaptersWriteIsAnalystOnly(t *testing.T) {
	body := `{"name":"Probe","source_name":"Probe","findings_path":".","title_field":"t","asset_field":"a","severity_field":"s"}`
	for role, want := range map[string]int{"Wrangler": http.StatusForbidden, "Magistrate": http.StatusForbidden, "RangeHand": http.StatusCreated, "Sheriff": http.StatusCreated} {
		app, cookie := appWithUser(t, role)
		req := httptest.NewRequest(http.MethodPost, "/api/adapters", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s creating an adapter: want %d got %d %s", role, want, rec.Code, rec.Body.String())
		}
	}
}
