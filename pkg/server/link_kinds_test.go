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

// handOut creates n findings on one asset, hands them to dana, and returns
// their ids and the owner's link.
var handOutBatch int

func handOut(t *testing.T, app *App, n int) ([]int, string) {
	t.Helper()
	ctx := context.Background()
	handOutBatch++
	var ids []int
	for i := 0; i < n; i++ {
		tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-" + strconv.Itoa(handOutBatch) + "-" + strconv.Itoa(i+1) + " kinds", Severity: "High", Domain: "Vulnerability",
			TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
		if err := app.Store.CreateTicket(ctx, &tk); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tk.ID)
	}
	token, err := app.Store.BulkUpdateStatusAndAssign(ctx, ids, "Assigned Out", "dana@rr.test", "", "sheriff@rr.test")
	if err != nil || token == "" {
		t.Fatalf("assigning out should mint an owner link: %v", err)
	}
	return ids, token
}

func send(app *App, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	return rec
}

// The owner's link asks; it cannot answer. Only an approver's link, minted by
// the Sheriff from Risk Reviews, can approve or deny.
func TestOwnerLinkCannotApproveItsOwnRequest(t *testing.T) {
	app, sheriff := appWithUser(t, "Sheriff")
	ids, owner := handOut(t, app, 1)
	if rec := send(app, http.MethodPost, "/api/share/"+owner+"/risk", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"type":"Risk Acceptance","rationale":"isolated"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner request: %d %s", rec.Code, rec.Body.String())
	}
	if rec := send(app, http.MethodPatch, "/api/share/"+owner+"/review", `{"action":"Approve","comment":"me","extension_days":30}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("an owner link must not approve, got %d %s", rec.Code, rec.Body.String())
	}
	// The Sheriff mints the approver's link with context for the approver
	rec := send(app, http.MethodPost, "/api/tickets/review-link", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"context":"replica has no external route, verified"}`, sheriff)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint approver link: %d %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)
	if minted.Token == "" || minted.Token == owner {
		t.Fatalf("the approver link must be its own token")
	}
	if rec := send(app, http.MethodPatch, "/api/share/"+minted.Token+"/review", `{"action":"Approve","actor":"Legal / Compliance","comment":"accepted","extension_days":90}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("approver link approves: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := app.Store.GetTicketByID(context.Background(), ids[0])
	if got.Status != "Risk Accepted" {
		t.Fatalf("status after approval: %q", got.Status)
	}
}

// The approver's link decides; it cannot act as the owner.
func TestApproverLinkCannotSubmitAFix(t *testing.T) {
	app, sheriff := appWithUser(t, "Sheriff")
	ids, owner := handOut(t, app, 1)
	send(app, http.MethodPost, "/api/share/"+owner+"/risk", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"type":"Time Extension","rationale":"next sprint"}`, nil)
	rec := send(app, http.MethodPost, "/api/tickets/review-link", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"context":"ok"}`, sheriff)
	var minted struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/share/" + minted.Token, `{"ticket_ids":[` + strconv.Itoa(ids[0]) + `],"patch_evidence":"x"}`},
		{http.MethodPost, "/api/share/" + minted.Token + "/risk", `{"ticket_ids":[` + strconv.Itoa(ids[0]) + `],"type":"Risk Acceptance","rationale":"x"}`},
		{http.MethodPost, "/api/share/" + minted.Token + "/reject", `{"ticket_ids":[` + strconv.Itoa(ids[0]) + `],"reason":"WRONG_OWNER","comment":"x"}`},
	} {
		if rec := send(app, c.method, c.path, c.body, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s with an approver link must be refused, got %d", c.method, c.path, rec.Code)
		}
	}
	// and the owner page does not open on it
	if rec := send(app, http.MethodGet, "/api/share/"+minted.Token, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("the owner inbox must not open on an approver link, got %d", rec.Code)
	}
}

// What the Sheriff writes when minting the link is what the approver reads.
func TestSheriffContextReachesTheApprover(t *testing.T) {
	app, sheriff := appWithUser(t, "Sheriff")
	ids, owner := handOut(t, app, 1)
	send(app, http.MethodPost, "/api/share/"+owner+"/risk", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"type":"Risk Acceptance","rationale":"replica, no external route"}`, nil)
	rec := send(app, http.MethodPost, "/api/tickets/review-link", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"context":"verified the subnet has no inbound route"}`, sheriff)
	var minted struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)
	rec = send(app, http.MethodGet, "/api/share/"+minted.Token+"/review", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approver payload: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Tickets []domain.Ticket `json:"tickets"`
	}
	json.Unmarshal(rec.Body.Bytes(), &payload)
	if len(payload.Tickets) != 1 || !strings.Contains(payload.Tickets[0].LatestComment, "no inbound route") || !strings.Contains(payload.Tickets[0].RiskRationale, "no external route") {
		t.Fatalf("the approver must see the owner's rationale and the Sheriff's context: %+v", payload.Tickets)
	}
}

// Deny from Risk Reviews acts on the one finding, not every finding on the link.
func TestDenyOneLeavesTheOthersPending(t *testing.T) {
	app, sheriff := appWithUser(t, "Sheriff")
	ids, owner := handOut(t, app, 2)
	send(app, http.MethodPost, "/api/share/"+owner+"/risk", `{"type":"Time Extension","rationale":"both please"}`, nil)
	if rec := send(app, http.MethodPatch, "/api/tickets/"+strconv.Itoa(ids[0])+"/review", `{"action":"Deny","comment":"patch it"}`, sheriff); rec.Code != http.StatusOK {
		t.Fatalf("sheriff deny: %d %s", rec.Code, rec.Body.String())
	}
	first, _ := app.Store.GetTicketByID(context.Background(), ids[0])
	second, _ := app.Store.GetTicketByID(context.Background(), ids[1])
	if first.Status != "Assigned Out" || second.Status != "Pending Risk Approval" {
		t.Fatalf("deny one: first=%q second=%q", first.Status, second.Status)
	}
	// and an approver with two on the link can decide one at a time too
	rec := send(app, http.MethodPost, "/api/tickets/review-link", `{"ticket_ids":[`+strconv.Itoa(ids[1])+`],"context":"ok"}`, sheriff)
	var minted struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)
	if rec := send(app, http.MethodPatch, "/api/share/"+minted.Token+"/review", `{"action":"Approve","comment":"fine","extension_days":7,"ticket_ids":[`+strconv.Itoa(ids[1])+`]}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("approve the second: %d %s", rec.Code, rec.Body.String())
	}
}

// A link lives while the owner still has work on it. Once every finding on
// it has left that owner (returned, reassigned, patched, accepted) the link
// stops answering, well before its 90 days are up.
func TestLinkStopsWhenFindingsLeaveTheOwner(t *testing.T) {
	app, sheriff := appWithUser(t, "Sheriff")
	ids, owner := handOut(t, app, 2)
	open := func() int { return send(app, http.MethodGet, "/api/share/"+owner, "", nil).Code }
	if open() != http.StatusOK {
		t.Fatalf("a fresh link opens")
	}
	// one finding returned: the other is still dana's, the link lives
	if rec := send(app, http.MethodPost, "/api/share/"+owner+"/reject", `{"ticket_ids":[`+strconv.Itoa(ids[0])+`],"reason":"WRONG_OWNER","comment":"not mine"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("return: %d %s", rec.Code, rec.Body.String())
	}
	if open() != http.StatusOK {
		t.Fatalf("one finding returned, one still owned: the link must still open")
	}
	// the last one verified patched from the office: nothing left on the link
	if rec := send(app, http.MethodPatch, "/api/tickets/bulk", `{"ticket_ids":[`+strconv.Itoa(ids[1])+`],"status":"Patched","comment":"rescan clean"}`, sheriff); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if c := open(); c != http.StatusNotFound {
		t.Fatalf("every finding left the owner: the link must stop, got %d", c)
	}
	// reassigning to someone else mints their link and ends the old one
	ids2, owner2 := handOut(t, app, 1)
	if rec := send(app, http.MethodPatch, "/api/tickets/bulk", `{"ticket_ids":[`+strconv.Itoa(ids2[0])+`],"status":"Assigned Out","assignee":"sam@rr.test","comment":"wrong team"}`, sheriff); rec.Code != http.StatusOK {
		t.Fatalf("reassign: %d %s", rec.Code, rec.Body.String())
	}
	if c := send(app, http.MethodGet, "/api/share/"+owner2, "", nil).Code; c != http.StatusNotFound {
		t.Fatalf("dana's link must stop once the finding is sam's, got %d", c)
	}
}
