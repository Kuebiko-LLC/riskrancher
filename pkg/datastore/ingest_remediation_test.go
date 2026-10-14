package datastore_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The scanner's fix travels with the finding: batch ingest stores the
// remediation, and a re-scan with a changed fix updates it.
func TestIngestBatch_KeepsRecommendedRemediation(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 fix", Severity: "High", Description: "old desc", RecommendedRemediation: "upgrade to 2.17.1"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	var fix string
	s.DB.QueryRow(`SELECT COALESCE(recommended_remediation,'') FROM tickets WHERE title = 'CVE-0000-0001 fix'`).Scan(&fix)
	if fix != "upgrade to 2.17.1" {
		t.Fatalf("batch ingest must keep the remediation, got %q", fix)
	}
	batch[0].RecommendedRemediation = "upgrade to 2.17.2"
	batch[0].Description = "new desc"
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow(`SELECT COALESCE(recommended_remediation,'') FROM tickets WHERE title = 'CVE-0000-0001 fix'`).Scan(&fix)
	if fix != "upgrade to 2.17.2" {
		t.Fatalf("a re-scan with a changed fix must update it, got %q", fix)
	}
}
