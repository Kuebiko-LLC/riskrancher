package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func seedFinding(t *testing.T, app *App, title string) domain.Ticket {
	t.Helper()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: title, Severity: "Critical", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := app.Store.CreateTicket(context.Background(), &tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

// Paging keeps the filter and asset you were looking at.
func TestPaginationKeepsFilters(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	seedFinding(t, app, "CVE-0000-0001 page")
	req := httptest.NewRequest(http.MethodGet, "/dashboard?tab=holding_pen&filter=critical&asset=payments-api", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: %d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, "filter=critical") || !strings.Contains(page, "asset=payments-api") {
		t.Fatalf("the Next and Previous links must carry filter and asset")
	}
}

// The Sheriff's home is the admin page, but a link into a filtered
// dashboard still opens the dashboard.
func TestSheriffCanOpenFilteredDashboard(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	seedFinding(t, app, "CVE-0000-0002 sheriff")
	get := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := get("/dashboard"); c != http.StatusSeeOther {
		t.Fatalf("plain /dashboard sends the Sheriff to admin, got %d", c)
	}
	if c := get("/dashboard?tab=holding_pen&filter=critical"); c != http.StatusOK {
		t.Fatalf("a filtered dashboard link must open for the Sheriff, got %d", c)
	}
	page, _ := fsReadUI("templates/components/admin_metrics.gohtml")
	if !strings.Contains(page, `href="/dashboard?tab=holding_pen&filter=critical"`) || !strings.Contains(page, `href="/dashboard?tab=holding_pen&filter=overdue"`) {
		t.Fatalf("the KPI cards must link into the filtered dashboard")
	}
}

// Every change to a finding is on the record and the drawer can show it.
func TestTicketActivityRoute(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	tk := seedFinding(t, app, "CVE-0000-0003 history")
	if _, err := app.Store.BulkUpdateStatusAndAssign(context.Background(), []int{tk.ID}, "Assigned Out", "dana@rr.test", "yours", "sheriff@rr.test"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tickets/"+strconv.Itoa(tk.ID)+"/activity", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
	}
	var entries []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &entries)
	var sawAssign bool
	for _, e := range entries {
		if e["type"] == "assigned_to" && e["actor"] == "sheriff@rr.test" && e["new_value"] == "dana@rr.test" {
			sawAssign = true
		}
	}
	if !sawAssign || len(entries) < 3 {
		t.Fatalf("expected the status change, assignment and comment on the record, got %v", entries)
	}
	src, _ := fsReadUI("static/dashboard.js")
	if !strings.Contains(src, "/api/tickets/${id}/activity") {
		t.Fatalf("the drawer must load the finding's history")
	}
}
