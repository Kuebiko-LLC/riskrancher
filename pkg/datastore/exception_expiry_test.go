package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// An accepted risk is deferred, not closed: when its expiry passes, the
// sweep puts it back on the queue with a fresh clock from the matrix and a
// line in the activity. One that has not expired is left alone.
func TestReopenExpiredExceptions_PutsFindingBackOnQueue(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	mk := func(title string) int {
		tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "legacy-billing", Title: title, Severity: "Critical", Domain: "Vulnerability"}
		if err := s.CreateTicket(ctx, &tk); err != nil {
			t.Fatal(err)
		}
		return tk.ID
	}
	expired, live := mk("TLS 1.0 expired"), mk("TLS 1.0 live")
	for _, id := range []int{expired, live} {
		if err := s.RequestRiskException(ctx, []int{id}, "Risk Acceptance", "refactor pending", "finance@rr.test"); err != nil {
			t.Fatal(err)
		}
		if err := s.ReviewRiskRequest(ctx, []int{id}, "Approve", "cfo@rr.test", "signed", 180); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE tickets SET exception_expires_at = DATETIME('now', '-1 day'), remediation_due_date = DATETIME('now', '-100 days') WHERE id = ?`, expired); err != nil {
		t.Fatal(err)
	}

	n, err := s.ReopenExpiredExceptions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("one expired exception to reopen, got n=%d err=%v", n, err)
	}
	e, _ := s.GetTicketByID(ctx, expired)
	l, _ := s.GetTicketByID(ctx, live)
	if e.Status != "Waiting to be Triaged" || l.Status != "Risk Accepted" {
		t.Fatalf("expired=%q live=%q", e.Status, l.Status)
	}
	if days := int(time.Until(e.RemediationDueDate).Hours()/24 + 0.5); days != 14 {
		t.Fatalf("reopened Critical gets the matrix clock of 14 days, got %d", days)
	}
	if e.ExceptionExpiresAt != nil {
		t.Fatalf("the expiry is cleared once it has fired")
	}
	var activity int
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_activity WHERE ticket_id = ? AND activity_type = 'exception_expired'`, expired).Scan(&activity)
	if activity != 1 {
		t.Fatalf("the reopen is on the record, got %d activity rows", activity)
	}
	// Running again finds nothing
	if n, _ := s.ReopenExpiredExceptions(ctx); n != 0 {
		t.Fatalf("second sweep must find nothing, got %d", n)
	}
}
