package datastore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Once an asset is in the inventory, a finding that lands on it is scored:
// the scanner's severity as the base, times exposure and criticality, banded.
// The scanner's word is kept beside the result. An asset the tool does not
// know keeps the scanner's word.

type scored struct {
	severity, scanner string
	score             *float64
	due               time.Time
	kev               bool
}

func readScored(t *testing.T, s *datastore.SQLiteStore, title string) scored {
	t.Helper()
	var r scored
	if err := s.DB.QueryRow(`SELECT severity, scanner_severity, rubric_score, remediation_due_date, COALESCE(is_cisa_kev, 0) FROM tickets WHERE title = ?`, title).
		Scan(&r.severity, &r.scanner, &r.score, &r.due, &r.kev); err != nil {
		t.Fatalf("ticket %q: %v", title, err)
	}
	return r
}

func daysUntil(d time.Time) int { return int(time.Until(d).Hours()/24 + 0.5) }

func paymentsAPI(t *testing.T, s *datastore.SQLiteStore) {
	t.Helper()
	if err := s.UpsertAssets(context.Background(), []domain.Asset{{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel", Owner: "Payments"}}); err != nil {
		t.Fatal(err)
	}
}

func TestBatchIngest_ScoresAFindingOnAKnownAsset(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Outdated OpenSSL", Severity: "High"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Outdated OpenSSL")
	if got.severity != "Critical" || got.scanner != "High" || got.score == nil || *got.score != 12 {
		t.Fatalf("High x internet x crown-jewel = 12, Critical; got %+v", got)
	}
	if d := daysUntil(got.due); d != 14 {
		t.Fatalf("the clock follows the computed severity (Critical row of the matrix, 14 days), got %d", d)
	}
	var hash string
	s.DB.QueryRow(`SELECT dedupe_hash FROM tickets WHERE title = 'Outdated OpenSSL'`).Scan(&hash)
	if hash != hashOf("Nessus", "payments-api", "Outdated OpenSSL") {
		t.Fatal("the dedupe hash never includes the severity")
	}
}

func TestBatchIngest_UnknownAssetKeepsTheScannersWord(t *testing.T) {
	s := newRulesStore(t)
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "mystery-box", Title: "Outdated OpenSSL", Severity: "high"}}
	if err := s.ProcessIngestionBatch(context.Background(), "Nessus", "mystery-box", batch); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Outdated OpenSSL")
	if got.severity != "High" || got.scanner != "High" || got.score != nil {
		t.Fatalf("no inventory row: severity stays the scanner's normalized word, no score; got %+v", got)
	}
}

func TestBatchIngest_SeverityRuleWinsOverTheRubric(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	if _, err := s.DB.Exec(`INSERT INTO auto_triage_rules (match_asset, action_type, action_value) VALUES ('payments-api', 'DowngradeSeverity', 'Low')`); err != nil {
		t.Fatal(err)
	}
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Outdated OpenSSL", Severity: "High"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Outdated OpenSSL")
	if got.severity != "Low" || got.score == nil || *got.score != 12 {
		t.Fatalf("an explicit rule overrides the band; the score is still recorded; got %+v", got)
	}
}

func TestBatchIngest_KEVWinsOverRubricAndRules(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`), &feed)
	if _, err := s.SyncCISACatalog(ctx, &feed); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAssets(ctx, []domain.Asset{{AssetIdentifier: "dev-sandbox", Exposure: "isolated", Criticality: "dev"}}); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(`INSERT INTO auto_triage_rules (match_asset, action_type, action_value) VALUES ('dev-sandbox', 'DowngradeSeverity', 'Low')`)
	batch := []domain.Ticket{{Source: "Trivy", AssetIdentifier: "dev-sandbox", Title: "CVE-2021-44228 Log4Shell", Severity: "Critical"}}
	if err := s.ProcessIngestionBatch(ctx, "Trivy", "dev-sandbox", batch); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "CVE-2021-44228 Log4Shell")
	if got.severity != "Critical" || !got.kev || got.score == nil || *got.score != 1 {
		t.Fatalf("a listed CVE is Critical whatever the math or a rule says; got %+v", got)
	}
	if d := daysUntil(got.due); d != 14 {
		t.Fatalf("Critical clock, got %d days", d)
	}
}

func TestCreateTicket_ScoresTooOnTheSinglePath(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	tk := domain.Ticket{Source: "Manual", AssetIdentifier: "payments-api", Title: "Hand-written finding", Severity: "Medium"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Hand-written finding")
	if got.severity != "High" || got.scanner != "Medium" || got.score == nil || *got.score != 8 {
		t.Fatalf("Medium x 2 x 2 = 8, High; got %+v", got)
	}
	back, err := s.GetTicketByID(ctx, tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.ScannerSeverity != "Medium" || back.RubricScore == nil || *back.RubricScore != 8 {
		t.Fatalf("GetTicketByID carries the scanner's word and the score; got %q %v", back.ScannerSeverity, back.RubricScore)
	}
}

func TestBatchIngest_InfoStaysInfoOnAKnownAsset(t *testing.T) {
	s := newRulesStore(t)
	paymentsAPI(t, s)
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Banner disclosure", Severity: "Info"}}
	if err := s.ProcessIngestionBatch(context.Background(), "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Banner disclosure")
	if got.severity != "Info" || got.score == nil || *got.score != 0 {
		t.Fatalf("nothing to prioritize: Info stays Info with score 0; got %+v", got)
	}
}

// A finding that was closed by a scan and comes back takes the incoming
// severity with it, not the one it had when it left.
func TestIngest_ReopenTakesTheIncomingSeverity(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	first := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0002 back", Severity: "High"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", first); err != nil {
		t.Fatal(err)
	}
	other := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "something else", Severity: "Low"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", other); err != nil {
		t.Fatal(err)
	}
	again := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0002 back", Severity: "Critical"}}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", again); err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "CVE-0000-0002 back")
	if got.severity != "Critical" || got.scanner != "Critical" {
		t.Fatalf("reopened finding carries the incoming severity; got %+v", got)
	}
	if d := daysUntil(got.due); d != 14 {
		t.Fatalf("Critical clock on reopen, got %d days", d)
	}
}
