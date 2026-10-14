package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// A hand verify from the dashboard closes the finding as patched and stamps
// patched_at, so MTTR counts it the same as a scan-detected fix.
func TestVerify_SetsPatchedAt(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 verify", Severity: "High", Domain: "Vulnerability"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Patched", "", "verified by rescan", "sheriff@rr.test"); err != nil {
		t.Fatal(err)
	}
	var patched *time.Time
	s.DB.QueryRow(`SELECT patched_at FROM tickets WHERE id = ?`, tk.ID).Scan(&patched)
	if patched == nil {
		t.Fatalf("verify must stamp patched_at")
	}
	// Reopening clears it
	if _, err := s.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Waiting to be Triaged", "", "came back", "sheriff@rr.test"); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow(`SELECT patched_at FROM tickets WHERE id = ?`, tk.ID).Scan(&patched)
	if patched != nil {
		t.Fatalf("leaving Patched must clear patched_at")
	}
}

// MTTR counts findings closed by hand, not only those a scan closed.
func TestMTTR_CountsManualVerifies(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0002 mttr", Severity: "High", Domain: "Vulnerability"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE tickets SET created_at = DATETIME('now', '-10 days') WHERE id = ?`, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Patched", "", "verified", "sheriff@rr.test"); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetSheriffAnalytics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.GlobalMTTRDays != 10 {
		t.Fatalf("a finding found 10 days ago and verified today is a 10-day MTTR, got %d", m.GlobalMTTRDays)
	}
}
