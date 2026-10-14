package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// pendingRequest creates a finding, hands it out, and files a time-extension
// request on it, returning the link token and the ticket id.
func pendingRequest(t *testing.T, app *App) (string, int) {
	t.Helper()
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 router", Severity: "High", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := app.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	token, err := app.Store.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Assigned Out", "dana@rr.test", "", "sheriff@rr.test")
	if err != nil || token == "" {
		t.Fatalf("assigning out should mint a link: %v", err)
	}
	if err := app.Store.RequestRiskException(ctx, []int{tk.ID}, "Time Extension", "sprint lands late", "dana@rr.test"); err != nil {
		t.Fatal(err)
	}
	return token, tk.ID
}

func ticketState(t *testing.T, app *App, id int) (status, comment string, extensions int) {
	t.Helper()
	tk, err := app.Store.GetTicketByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tk.Status, tk.LatestComment, tk.ExtensionCount
}

// The approver's page sends its decision as the magistrate script does, and
// the router must accept it: Approve moves the clock, Deny hands it back.
func TestApproverPortal_ApproveAndDenyThroughRouter(t *testing.T) {
	app := routerApp(t)
	token, id := pendingRequest(t, app)

	body := `{"action":"Approve","actor":"Legal / Compliance","comment":"once","extension_days":14}`
	req := httptest.NewRequest(http.MethodPatch, "/api/share/"+token+"/review", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve through the router: %d %s", rec.Code, rec.Body.String())
	}
	if status, _, ext := ticketState(t, app, id); status != "Assigned Out" || ext != 1 {
		t.Fatalf("approved extension: status=%q extensions=%d", status, ext)
	}

	// A second request, denied this time
	if err := app.Store.RequestRiskException(context.Background(), []int{id}, "Time Extension", "again", "dana@rr.test"); err != nil {
		t.Fatal(err)
	}
	body = `{"action":"Deny","actor":"Legal / Compliance","comment":"patch it","extension_days":0}`
	req = httptest.NewRequest(http.MethodPatch, "/api/share/"+token+"/review", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny through the router: %d %s", rec.Code, rec.Body.String())
	}
	if status, comment, _ := ticketState(t, app, id); status != "Assigned Out" || !strings.Contains(comment, "patch it") {
		t.Fatalf("denied request: status=%q comment=%q", status, comment)
	}
}

// The Sheriff's deny button on the Risk Reviews tab goes through the same
// portal review route with the action the store understands.
func TestSheriffDeny_UsesPortalReviewRoute(t *testing.T) {
	app := routerApp(t)
	token, id := pendingRequest(t, app)
	src, err := fsReadUI("static/admin.js")
	if err != nil {
		t.Fatal(err)
	}
	// The script must name the portal review route and the capitalized action
	if !strings.Contains(src, "/api/share/${token}/review") || !strings.Contains(src, "action: 'Deny'") {
		t.Fatalf("admin.js deny must call PATCH /api/share/{token}/review with action Deny")
	}
	if !strings.Contains(src, `"/review/" + newBatchToken`) {
		t.Fatalf("admin.js copy-link must hand out the approver's /review/ page, not the owner's /share/")
	}
	body := `{"action":"Deny","comment":"patch it","extension_days":0,"actor":"Sheriff"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/share/"+token+"/review", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sheriff deny: %d %s", rec.Code, rec.Body.String())
	}
	if status, comment, _ := ticketState(t, app, id); status != "Assigned Out" || !strings.Contains(comment, "patch it") {
		t.Fatalf("denied: status=%q comment=%q", status, comment)
	}
	_ = json.Valid
}
