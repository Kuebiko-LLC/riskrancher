package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func auditRows(t *testing.T, app *App) []domain.FeedItem {
	t.Helper()
	rows, _, err := app.Store.GetPaginatedActivityFeed(context.Background(), "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func hasRow(rows []domain.FeedItem, actor, action string) bool {
	for _, r := range rows {
		if r.Actor == actor && strings.Contains(r.ActivityType, action) {
			return true
		}
	}
	return false
}

// The audit log records every change and every failure, with a real actor:
// sign-ins by the email tried, portal actions by the owner the link was for.
func TestAuditLogsLoginAndPortalActor(t *testing.T) {
	app, _ := appWithUser(t, "Sheriff")
	// a failed sign-in is a row, by the email that tried
	send(app, http.MethodPost, "/api/auth/login", `{"email":"nobody@rr.test","password":"wrong"}`, nil)
	if !hasRow(auditRows(t, app), "nobody@rr.test", "POST /api/auth/login") {
		t.Fatalf("a failed login must be on the record: %v", auditRows(t, app))
	}
	// the owner's action through their link is a row by the owner
	ids, owner := handOut(t, app, 1)
	if rec := send(app, http.MethodPatch, "/api/share/"+owner, `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"patch_evidence":"pr 12"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("submit fix: %d %s", rec.Code, rec.Body.String())
	}
	if !hasRow(auditRows(t, app), "dana@rr.test", "PATCH /api/share/") {
		t.Fatalf("a portal action must carry the owner as actor, got %v", auditRows(t, app))
	}
	// a refused call is a row too, before any handler runs
	send(app, http.MethodGet, "/api/admin/users", "", nil)
	if !hasRow(auditRows(t, app), "Unknown User", "GET /api/admin/users") {
		t.Fatalf("a refused call must be on the record: %v", auditRows(t, app))
	}
}

// The account you just made or signed in with is active, and the response
// says so instead of showing a zero value.
func TestSignInResponseShowsAnActiveAccount(t *testing.T) {
	app, _ := appWithUser(t, "Sheriff")
	rec := send(app, http.MethodPost, "/api/auth/login", `{"email":"Sheriff@rr.test","password":"x"}`, nil)
	_ = rec // the fixture's hash is not a real password; use a fresh registration instead
	app2 := routerApp(t)
	rec = send(app2, http.MethodPost, "/api/auth/register", `{"email":"first@rr.test","full_name":"First","password":"correct-horse-battery","global_role":"Sheriff"}`, nil)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"is_active":true`) || strings.Contains(rec.Body.String(), "0001-01-01") {
		t.Fatalf("register response: %d %s", rec.Code, rec.Body.String())
	}
	rec = send(app2, http.MethodPost, "/api/auth/login", `{"email":"first@rr.test","password":"correct-horse-battery"}`, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"is_active":true`) || strings.Contains(rec.Body.String(), "0001-01-01") {
		t.Fatalf("login response: %d %s", rec.Code, rec.Body.String())
	}
}
