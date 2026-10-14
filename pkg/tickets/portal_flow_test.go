package tickets

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

// The owner's portal and the approver's portal are authorized by their link,
// not by an account, and every action lands on the ticket.
func TestPortalFlow_OwnerFixesAndApproverRules(t *testing.T) {
	h, db := setupTestTickets(t)
	defer db.Close()
	ctx := context.Background()

	// Given two assigned findings handed out as one portal link
	var ids []int
	for _, title := range []string{"CVE-0000-0001 example", "CVE-0000-0002 example"} {
		tk := &domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: title, Severity: "High", Domain: "Vulnerability"}
		if err := h.Store.CreateTicket(ctx, tk); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tk.ID)
	}
	token, err := h.Store.BulkUpdateStatusAndAssign(ctx, ids, "Assigned Out", "dana@rr.test", "yours", "sheriff@rr.test")
	if err != nil || token == "" {
		t.Fatalf("assigning out should mint a portal token: %v %q", err, token)
	}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("token", strings.TrimPrefix(strings.Split(strings.TrimPrefix(path, "/api/share/"), "/")[0], ""))
		rec := httptest.NewRecorder()
		switch {
		case method == http.MethodGet:
			h.HandleMagicLink(rec, req)
		case method == http.MethodPatch && strings.HasSuffix(path, "/review"):
			// the approver acts on a link of their own kind, over the owner link's findings
			ownerBatch, err := h.Store.GetMagicBatch(ctx, req.PathValue("token"))
			if err != nil {
				t.Fatalf("owner link: %v", err)
			}
			approver, err := h.Store.MintApproverLink(ctx, ownerBatch.TicketIDs, "sheriff@rr.test", "")
			if err != nil {
				t.Fatalf("mint approver link: %v", err)
			}
			req.SetPathValue("token", approver)
			h.HandleMagistrateReview(rec, req)
		case method == http.MethodPatch:
			h.HandleMagicLinkSubmit(rec, req)
		case strings.HasSuffix(path, "/risk"):
			h.HandleSubmitRiskRequest(rec, req)
		}
		return rec
	}

	// The owner opens the link and sees their findings, nobody else's
	rec := call(http.MethodGet, "/api/share/"+token, "")
	var page struct {
		Assignee string          `json:"assignee"`
		Tickets  []domain.Ticket `json:"tickets"`
	}
	json.Unmarshal(rec.Body.Bytes(), &page)
	if rec.Code != http.StatusOK || len(page.Tickets) != 2 || page.Assignee != "dana@rr.test" {
		t.Fatalf("portal should list the two assigned findings for dana: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/share/not-a-token", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a bad link must 404, got %d", rec.Code)
	}

	// The owner submits a fix on the first finding
	rec = call(http.MethodPatch, "/api/share/"+token, `{"ticket_ids":[`+itoa(ids[0])+`],"patch_evidence":"upgraded to 2.17.1, re-scan clean"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit fix: %d %s", rec.Code, rec.Body.String())
	}
	var status, evidence string
	db.QueryRow(`SELECT status, COALESCE(patch_evidence,'') FROM tickets WHERE id = ?`, ids[0]).Scan(&status, &evidence)
	if status != "Pending Verification" || evidence == "" {
		t.Fatalf("a submitted fix waits for verification with its evidence: %q %q", status, evidence)
	}

	// The owner asks for more time on the second finding
	rec = call(http.MethodPost, "/api/share/"+token+"/risk", `{"ticket_ids":[`+itoa(ids[1])+`],"type":"Time Extension","rationale":"change window is in three weeks"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("risk request: %d %s", rec.Code, rec.Body.String())
	}
	var before time.Time
	db.QueryRow(`SELECT status, remediation_due_date FROM tickets WHERE id = ?`, ids[1]).Scan(&status, &before)
	if status != "Pending Risk Approval" {
		t.Fatalf("a request waits for the approver, got %q", status)
	}

	// The approver grants 14 days under a policy that allows one extension
	db.Exec(`DELETE FROM sla_policies`)
	db.Exec(`INSERT INTO sla_policies (domain, severity, days_to_triage, days_to_remediate, max_extensions) VALUES ('Vulnerability', 'High', 3, 14, 1)`)
	rec = call(http.MethodPatch, "/api/share/"+token+"/review", `{"action":"Approve","actor":"magistrate@rr.test","comment":"ok once","extension_days":14}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	var after time.Time
	var count int
	db.QueryRow(`SELECT status, remediation_due_date, extension_count FROM tickets WHERE id = ?`, ids[1]).Scan(&status, &after, &count)
	if status != "Assigned Out" || count != 1 || int(after.Sub(before).Hours()/24+0.5) != 14 {
		t.Fatalf("an approved extension moves the clock 14 days and counts: status=%q count=%d moved=%v", status, count, after.Sub(before))
	}

	// A second extension exceeds the policy's cap
	call(http.MethodPost, "/api/share/"+token+"/risk", `{"ticket_ids":[`+itoa(ids[1])+`],"type":"Time Extension","rationale":"again"}`)
	rec = call(http.MethodPatch, "/api/share/"+token+"/review", `{"action":"Approve","actor":"magistrate@rr.test","comment":"no","extension_days":14}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("beyond max_extensions the approver gets 409, got %d %s", rec.Code, rec.Body.String())
	}

	// Risk acceptance is its own status with an expiry the approver sets
	call(http.MethodPost, "/api/share/"+token+"/risk", `{"ticket_ids":[`+itoa(ids[1])+`],"type":"Risk Acceptance","rationale":"legacy, refactor in six months"}`)
	rec = call(http.MethodPatch, "/api/share/"+token+"/review", `{"action":"Approve","actor":"magistrate@rr.test","comment":"accepted","extension_days":180}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept risk: %d %s", rec.Code, rec.Body.String())
	}
	var approvedBy string
	var expires time.Time
	db.QueryRow(`SELECT status, COALESCE(risk_approved_by,''), exception_expires_at FROM tickets WHERE id = ?`, ids[1]).Scan(&status, &approvedBy, &expires)
	if status != "Risk Accepted" || approvedBy != "magistrate@rr.test" || int(time.Until(expires).Hours()/24+0.5) != 180 {
		t.Fatalf("accepted risk: status=%q by=%q expires in %v", status, approvedBy, time.Until(expires))
	}

	// A denial hands the finding back to the owner with the reason
	tk := &domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0003 example", Severity: "Low"}
	h.Store.CreateTicket(ctx, tk)
	token2, _ := h.Store.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Assigned Out", "dana@rr.test", "", "sheriff@rr.test")
	call(http.MethodPost, "/api/share/"+token2+"/risk", `{"type":"Risk Acceptance","rationale":"meh"}`)
	rec = call(http.MethodPatch, "/api/share/"+token2+"/review", `{"action":"Deny","actor":"magistrate@rr.test","comment":"fix it"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	var comment string
	db.QueryRow(`SELECT status, COALESCE(latest_comment,'') FROM tickets WHERE id = ?`, tk.ID).Scan(&status, &comment)
	if status != "Assigned Out" || !strings.Contains(comment, "fix it") {
		t.Fatalf("a denial returns the finding with the reason: %q %q", status, comment)
	}
	var activity int
	db.QueryRow(`SELECT COUNT(*) FROM ticket_activity WHERE ticket_id IN (?, ?, ?)`, ids[0], ids[1], tk.ID).Scan(&activity)
	if activity < 6 {
		t.Fatalf("every portal action should be in the activity log, got %d rows", activity)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
