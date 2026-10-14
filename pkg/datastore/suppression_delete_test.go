package datastore_test

import (
	"context"
	"testing"

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
	if err := s.DeleteSuppressionRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if status, _, _ = ticketStatus(t, s, rule.DedupeHash); status != "Waiting to be Triaged" {
		t.Fatalf("deleting the rule reopens the finding, got %q", status)
	}
	if err := s.ProcessIngestionBatch(ctx, "ZAP", "marketing-site", batch); err != nil {
		t.Fatal(err)
	}
	if status, _, _ = ticketStatus(t, s, rule.DedupeHash); status != "Waiting to be Triaged" {
		t.Fatalf("the next scan keeps it open, got %q", status)
	}
}
