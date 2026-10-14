package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The dashboard drawer saves severity, description and remediation with a
// comment, and nothing else. The finding's status and owner must survive.
func TestDrawerEdit_KeepsStatusAndAssignee(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 drawer", Severity: "High", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := app.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Assigned Out", "dana@rr.test", "", "sheriff@rr.test"); err != nil {
		t.Fatal(err)
	}

	// The exact body dashboard.js sends from the drawer
	body := `{"severity":"Medium","comment":"downgraded: not reachable from the internet","description":"edited","recommended_remediation":"upgrade","actor":"Analyst"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/tickets/"+strconv.Itoa(tk.ID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("drawer save: %d %s", rec.Code, rec.Body.String())
	}
	got, err := app.Store.GetTicketByID(ctx, tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "Assigned Out" || got.Assignee != "dana@rr.test" {
		t.Fatalf("status and owner must survive a drawer edit: status=%q assignee=%q", got.Status, got.Assignee)
	}
	if got.Severity != "Medium" || got.Description != "edited" || got.RecommendedRemediation != "upgrade" || !strings.Contains(got.LatestComment, "downgraded") {
		t.Fatalf("edited fields: severity=%q description=%q remediation=%q comment=%q", got.Severity, got.Description, got.RecommendedRemediation, got.LatestComment)
	}
}
