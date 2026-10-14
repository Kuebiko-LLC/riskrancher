package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// A finding that was auto-closed and comes back on a later scan reopens
// with the clock from the SLA matrix, not a number in the code.
func TestIngest_ReopenUsesSLAMatrix(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	finding := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 back", Severity: "Critical"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", finding); err != nil {
		t.Fatal(err)
	}
	// The next scan on the asset does not have it: closed as patched
	other := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "something else", Severity: "Low"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", other); err != nil {
		t.Fatal(err)
	}
	var status string
	s.DB.QueryRow(`SELECT status FROM tickets WHERE title = 'CVE-0000-0001 back'`).Scan(&status)
	if status != "Patched" {
		t.Fatalf("missing from the scan should close it, got %q", status)
	}
	// It comes back
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", finding); err != nil {
		t.Fatal(err)
	}
	var due time.Time
	var patched *time.Time
	s.DB.QueryRow(`SELECT status, remediation_due_date, patched_at FROM tickets WHERE title = 'CVE-0000-0001 back'`).Scan(&status, &due, &patched)
	if status != "Waiting to be Triaged" || patched != nil {
		t.Fatalf("reappearing finding reopens: status=%q patched=%v", status, patched)
	}
	if days := int(time.Until(due).Hours()/24 + 0.5); days != 14 {
		t.Fatalf("reopened Critical gets the matrix clock of 14 days, got %d", days)
	}
	// both scan decisions are on the record
	var closed, reopened int
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_activity a JOIN tickets t ON t.id = a.ticket_id WHERE t.title = 'CVE-0000-0001 back' AND a.activity_type = 'scan_closed'`).Scan(&closed)
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_activity a JOIN tickets t ON t.id = a.ticket_id WHERE t.title = 'CVE-0000-0001 back' AND a.activity_type = 'scan_reopened'`).Scan(&reopened)
	if closed != 1 || reopened != 1 {
		t.Fatalf("the scan writes history: closed=%d reopened=%d", closed, reopened)
	}
}
