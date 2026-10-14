package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Deleting a logged false positive puts the finding back on the queue and
// the next scan keeps it open.
func TestDeleteSuppressionRule_ReopensTheFinding(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	batch := []domain.Ticket{{Source: "ZAP", AssetIdentifier: "marketing-site", Title: "SQL Injection (possible)", Severity: "High"}}
	if err := s.ProcessIngestionBatch(ctx, "ZAP", "marketing-site", batch); err != nil {
		t.Fatal(err)
	}
	rule := &domain.SuppressionRule{DedupeHash: hashOf("ZAP", "marketing-site", "SQL Injection (possible)"), AssetIdentifier: "marketing-site", Rationale: "static site", Actor: "sheriff@rr.test"}
	if err := s.CreateSuppressionRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	status, _, _ := ticketStatus(t, s, rule.DedupeHash)
	if status != "False Positive" {
		t.Fatalf("logging closes it, got %q", status)
	}
	if _, err := s.DB.Exec(`UPDATE tickets SET remediation_due_date = DATETIME('now', '-100 days') WHERE dedupe_hash = ?`, rule.DedupeHash); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSuppressionRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if status, _, _ = ticketStatus(t, s, rule.DedupeHash); status != "Waiting to be Triaged" {
		t.Fatalf("deleting the rule reopens the finding, got %q", status)
	}
	// and it comes back with a fresh clock from the matrix, not the stale one
	var due time.Time
	s.DB.QueryRow(`SELECT remediation_due_date FROM tickets WHERE dedupe_hash = ?`, rule.DedupeHash).Scan(&due)
	if days := int(time.Until(due).Hours()/24 + 0.5); days != 30 {
		t.Fatalf("a reopened High gets the matrix clock of 30 days, got %d", days)
	}
	if err := s.ProcessIngestionBatch(ctx, "ZAP", "marketing-site", batch); err != nil {
		t.Fatal(err)
	}
	if status, _, _ = ticketStatus(t, s, rule.DedupeHash); status != "Waiting to be Triaged" {
		t.Fatalf("the next scan keeps it open, got %q", status)
	}
}
