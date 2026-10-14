package datastore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// One rules engine, on every path a finding can arrive by: direct creation and
// scanner batch ingest. A decision made once (a suppressed false positive, a
// severity rule, a routing rule) applies to every row, every scan.

func newRulesStore(t *testing.T) *datastore.SQLiteStore {
	t.Helper()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "rules.db"))
	t.Cleanup(func() { db.Close() })
	return datastore.NewSQLiteStore(db)
}

func hashOf(source, asset, title string) string {
	h := sha256.Sum256([]byte(source + "|" + asset + "|" + title))
	return hex.EncodeToString(h[:])
}

func ticketStatus(t *testing.T, s *datastore.SQLiteStore, hash string) (status, severity, assignee string) {
	t.Helper()
	if err := s.DB.QueryRow(`SELECT status, severity, assignee FROM tickets WHERE dedupe_hash = ?`, hash).Scan(&status, &severity, &assignee); err != nil {
		t.Fatalf("ticket %s not found: %v", hash[:8], err)
	}
	return
}

func TestCreateTicket_SuppressionMatchesTheHashItWillGet(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	// Given a logged false positive for this exact finding on this asset
	hash := hashOf("Semgrep", "jenkins-ci", "Hardcoded AWS secret")
	if _, err := s.DB.Exec(`INSERT INTO suppression_rules (dedupe_hash, asset_identifier, rationale, actor) VALUES (?, 'jenkins-ci', 'documented example key', 'sheriff')`, hash); err != nil {
		t.Fatal(err)
	}
	// When the finding is created without a precomputed hash
	tk := &domain.Ticket{Source: "Semgrep", AssetIdentifier: "jenkins-ci", Title: "Hardcoded AWS secret", Severity: "Critical"}
	if err := s.CreateTicket(ctx, tk); err != nil {
		t.Fatal(err)
	}
	// Then it lands already closed as a false positive
	if st, _, _ := ticketStatus(t, s, hash); st != "False Positive" {
		t.Fatalf("suppressed finding should be False Positive, got %q", st)
	}
}

func TestBatchIngest_AppliesPerHashSuppression(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	hash := hashOf("Trivy", "payments-api", "CVE-0000-0001 example")
	if _, err := s.DB.Exec(`INSERT INTO suppression_rules (dedupe_hash, asset_identifier, rationale, actor) VALUES (?, 'payments-api', 'not reachable', 'sheriff')`, hash); err != nil {
		t.Fatal(err)
	}
	batch := []domain.Ticket{{Source: "Trivy", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 example", Severity: "High", DedupeHash: hash, Status: "Waiting to be Triaged"}}
	if err := s.ProcessIngestionBatch(ctx, "Trivy", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ticketStatus(t, s, hash); st != "False Positive" {
		t.Fatalf("batch ingest must honor the suppression log, got %q", st)
	}
}

func TestBatchIngest_GlobalSuppressionDoesNotBreakTheIngest(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`INSERT INTO global_suppression_rules (match_title, rationale, actor) VALUES ('Cognitive complexity', 'not a security finding', 'sheriff')`); err != nil {
		t.Fatal(err)
	}
	hash := hashOf("SonarQube", "internal-wiki", "Cognitive complexity too high")
	batch := []domain.Ticket{{Source: "SonarQube", AssetIdentifier: "internal-wiki", Title: "Cognitive complexity too high", Severity: "Low", DedupeHash: hash, Status: "Waiting to be Triaged"}}
	// When a global rule matches, the ingest must still succeed
	if err := s.ProcessIngestionBatch(ctx, "SonarQube", "internal-wiki", batch); err != nil {
		t.Fatalf("a matching global rule must not fail the ingest: %v", err)
	}
	st, _, _ := ticketStatus(t, s, hash)
	if st != "False Positive" {
		t.Fatalf("globally suppressed finding should be False Positive, got %q", st)
	}
	// And a re-scan does not churn it: no description rewrite, no reopen
	if err := s.ProcessIngestionBatch(ctx, "SonarQube", "internal-wiki", batch); err != nil {
		t.Fatal(err)
	}
	var desc string
	s.DB.QueryRow(`SELECT COALESCE(description,'') FROM tickets WHERE dedupe_hash = ?`, hash).Scan(&desc)
	if desc != "" {
		t.Fatalf("suppression must not rewrite the description, got %q", desc)
	}
}

func TestBatchIngest_AppliesSeverityRule(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`INSERT INTO auto_triage_rules (match_asset, action_type, action_value) VALUES ('dev-sandbox', 'DowngradeSeverity', 'Low')`); err != nil {
		t.Fatal(err)
	}
	hash := hashOf("Trivy", "dev-sandbox", "CVE-0000-0002 example")
	batch := []domain.Ticket{{Source: "Trivy", AssetIdentifier: "dev-sandbox", Title: "CVE-0000-0002 example", Severity: "Critical", DedupeHash: hash, Status: "Waiting to be Triaged"}}
	if err := s.ProcessIngestionBatch(ctx, "Trivy", "dev-sandbox", batch); err != nil {
		t.Fatal(err)
	}
	if _, sev, _ := ticketStatus(t, s, hash); sev != "Low" {
		t.Fatalf("severity rule must apply on batch ingest, got %q", sev)
	}
}

func TestBatchIngest_AppliesRoutingRule(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`INSERT INTO routing_rules (rule_type, match_value, assignee, role) VALUES ('Asset', 'payments-api', 'dana@rr.test', 'Wrangler')`); err != nil {
		t.Fatal(err)
	}
	hash := hashOf("Nessus", "payments-api", "CVE-0000-0003 example")
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0003 example", Severity: "High", DedupeHash: hash, Status: "Waiting to be Triaged"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	st, _, assignee := ticketStatus(t, s, hash)
	if assignee != "dana@rr.test" || st != "Assigned Out" {
		t.Fatalf("routing rule must assign on batch ingest: status=%q assignee=%q", st, assignee)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_assignments a JOIN tickets t ON t.id = a.ticket_id WHERE t.dedupe_hash = ? AND a.assignee = 'dana@rr.test'`, hash).Scan(&n)
	if n != 1 {
		t.Fatalf("expected one assignment row, got %d", n)
	}
}

func TestRejectFromWrangler_ResetsTheOwnerAndKeepsTheReason(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	tk := &domain.Ticket{Source: "Nessus", AssetIdentifier: "customer-db", Title: "CVE-0000-0004 example", Severity: "High"}
	if err := s.CreateTicket(ctx, tk); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(`UPDATE tickets SET assignee = 'sam@rr.test', status = 'Assigned Out' WHERE id = ?`, tk.ID)
	if err := s.RejectTicketFromWrangler(ctx, []int{tk.ID}, "Not reproducible", "ran the check twice"); err != nil {
		t.Fatal(err)
	}
	var status, assignee, comment string
	s.DB.QueryRow(`SELECT status, assignee, COALESCE(latest_comment,'') FROM tickets WHERE id = ?`, tk.ID).Scan(&status, &assignee, &comment)
	if status != "Returned to Security" || assignee != "Unassigned" || comment == "" {
		t.Fatalf("reject must return the ticket, clear the owner, and keep the reason: status=%q assignee=%q comment=%q", status, assignee, comment)
	}
}

// Logging a false positive for a finding already in the queue closes it now and
// keeps it closed on the next scan.
func TestSuppressionRule_ClosesAnOpenFindingAndKeepsItClosed(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	hash := hashOf("Semgrep", "jenkins-ci", "Hardcoded AWS secret")
	batch := []domain.Ticket{{Source: "Semgrep", AssetIdentifier: "jenkins-ci", Title: "Hardcoded AWS secret", Severity: "Critical", DedupeHash: hash, Status: "Waiting to be Triaged"}}
	if err := s.ProcessIngestionBatch(ctx, "Semgrep", "jenkins-ci", batch); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ticketStatus(t, s, hash); st != "Waiting to be Triaged" {
		t.Fatalf("precondition: open finding, got %q", st)
	}
	// Then the analyst logs it as a false positive
	if err := s.CreateSuppressionRule(ctx, &domain.SuppressionRule{DedupeHash: hash, AssetIdentifier: "jenkins-ci", Rationale: "documented example key", Actor: "sheriff"}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ticketStatus(t, s, hash); st != "False Positive" {
		t.Fatalf("logging a false positive must close the open finding, got %q", st)
	}
	// And the next scan does not bring it back
	if err := s.ProcessIngestionBatch(ctx, "Semgrep", "jenkins-ci", batch); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ticketStatus(t, s, hash); st != "False Positive" {
		t.Fatalf("a logged false positive must stay closed on re-scan, got %q", st)
	}
}
