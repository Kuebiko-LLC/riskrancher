package datastore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Loading an inventory, saving the rubric, deleting an asset and loading a
// KEV catalog all re-decide the open findings they touch, the way ingest
// would decide them today. Closed findings are left alone, the clocks only
// move when the severity did, and every change is a line in the history.

func ingestHigh(t *testing.T, s *datastore.SQLiteStore, asset, title string) {
	t.Helper()
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: asset, Title: title, Severity: "High"}}
	if err := s.ProcessIngestionBatch(context.Background(), "Nessus", asset, batch); err != nil {
		t.Fatal(err)
	}
}

func activityCount(t *testing.T, s *datastore.SQLiteStore, title, kind string) int {
	t.Helper()
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_activity a JOIN tickets t ON t.id = a.ticket_id WHERE t.title = ? AND a.activity_type = ?`, title, kind).Scan(&n)
	return n
}

func TestRescoreAssets_RecomputesOpenFindingsFromTheScannersWord(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	ingestHigh(t, s, "payments-api", "Outdated OpenSSL")
	if _, err := s.DB.Exec(`UPDATE tickets SET created_at = datetime('now', '-10 days')`); err != nil {
		t.Fatal(err)
	}
	before := readScored(t, s, "Outdated OpenSSL")
	if before.severity != "High" || before.score != nil {
		t.Fatalf("precondition: unknown asset keeps High; got %+v", before)
	}

	paymentsAPI(t, s)
	n, err := s.RescoreAssets(ctx, []string{"payments-api"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("one finding changed, got %d", n)
	}
	got := readScored(t, s, "Outdated OpenSSL")
	if got.severity != "Critical" || got.scanner != "High" || got.score == nil || *got.score != 12 {
		t.Fatalf("rescored from the scanner's word: want Critical/High/12, got %+v", got)
	}
	// The clock runs from when the finding was found, not from the rescore
	if d := daysUntil(got.due); d != 4 {
		t.Fatalf("created 10 days ago + 14 = 4 days left, got %d", d)
	}
	var actor, oldV, newV string
	s.DB.QueryRow(`SELECT a.actor, a.old_value, a.new_value FROM ticket_activity a JOIN tickets t ON t.id = a.ticket_id WHERE t.title = 'Outdated OpenSSL' AND a.activity_type = 'rescored'`).Scan(&actor, &oldV, &newV)
	if actor != "Rubric" || oldV != "High" || newV != "Critical" {
		t.Fatalf("history line: %s %s -> %s", actor, oldV, newV)
	}
	var hash string
	s.DB.QueryRow(`SELECT dedupe_hash FROM tickets WHERE title = 'Outdated OpenSSL'`).Scan(&hash)
	if hash != hashOf("Nessus", "payments-api", "Outdated OpenSSL") {
		t.Fatal("the dedupe hash is untouched")
	}
	// Nothing to do the second time
	if n, _ := s.RescoreAssets(ctx, []string{"payments-api"}); n != 0 {
		t.Fatalf("second rescore changes nothing, got %d", n)
	}
}

func TestRescoreAssets_LeavesClosedFindingsAlone(t *testing.T) {
	s := newRulesStore(t)
	ingestHigh(t, s, "payments-api", "Patched already")
	s.DB.Exec(`UPDATE tickets SET status = 'Patched'`)
	paymentsAPI(t, s)
	n, _ := s.RescoreAssets(context.Background(), []string{"payments-api"})
	got := readScored(t, s, "Patched already")
	if n != 0 || got.severity != "High" || activityCount(t, s, "Patched already", "rescored") != 0 {
		t.Fatalf("closed findings are not rescored: n=%d %+v", n, got)
	}
}

func TestRescoreAssets_KEVStillForcesCritical(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`), &feed)
	if _, err := s.SyncCISACatalog(ctx, &feed); err != nil {
		t.Fatal(err)
	}
	batch := []domain.Ticket{{Source: "Trivy", AssetIdentifier: "dev-sandbox", Title: "CVE-2021-44228 Log4Shell", Severity: "Critical"}}
	if err := s.ProcessIngestionBatch(ctx, "Trivy", "dev-sandbox", batch); err != nil {
		t.Fatal(err)
	}
	s.UpsertAssets(ctx, []domain.Asset{{AssetIdentifier: "dev-sandbox", Exposure: "isolated", Criticality: "dev"}})
	s.RescoreAssets(ctx, []string{"dev-sandbox"})
	got := readScored(t, s, "CVE-2021-44228 Log4Shell")
	if got.severity != "Critical" || got.score == nil || *got.score != 1 {
		t.Fatalf("KEV wins after a rescore too; got %+v", got)
	}
}

func TestRescoreAssets_SeverityRuleStillWins(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	ingestHigh(t, s, "payments-api", "Outdated OpenSSL")
	s.DB.Exec(`INSERT INTO auto_triage_rules (match_asset, action_type, action_value) VALUES ('payments-api', 'DowngradeSeverity', 'Low')`)
	paymentsAPI(t, s)
	s.RescoreAssets(ctx, []string{"payments-api"})
	if got := readScored(t, s, "Outdated OpenSSL"); got.severity != "Low" {
		t.Fatalf("the rule still wins; got %+v", got)
	}
}

func TestDeleteAsset_ReturnsFindingsToTheScannersWord(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	ingestHigh(t, s, "payments-api", "Outdated OpenSSL")
	if got := readScored(t, s, "Outdated OpenSSL"); got.severity != "Critical" {
		t.Fatalf("precondition: scored Critical, got %+v", got)
	}
	n, err := s.DeleteAsset(ctx, "payments-api")
	if err != nil {
		t.Fatal(err)
	}
	got := readScored(t, s, "Outdated OpenSSL")
	if n != 1 || got.severity != "High" || got.score != nil {
		t.Fatalf("forgotten asset: back to the scanner's High, no score; n=%d %+v", n, got)
	}
	if _, err := s.DeleteAsset(ctx, "payments-api"); err == nil {
		t.Fatal("deleting an asset that is not there is an error")
	}
}

func TestRescoreAssets_NilMeansEveryInventoriedAsset(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	ingestHigh(t, s, "payments-api", "A")
	ingestHigh(t, s, "customer-db", "B")
	ingestHigh(t, s, "unknown-host", "C")
	s.UpsertAssets(ctx, []domain.Asset{
		{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel"},
		{AssetIdentifier: "customer-db", Exposure: "internal", Criticality: "crown-jewel"},
	})
	n, err := s.RescoreAssets(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A: 3x2x2=12 Critical (changed); B: 3x1x2=6 High (same severity, score recorded); C untouched
	if n != 1 {
		t.Fatalf("one severity changed, got %d", n)
	}
	if got := readScored(t, s, "B"); got.severity != "High" || got.score == nil || *got.score != 6 {
		t.Fatalf("B keeps High but gains its score; got %+v", got)
	}
	if got := readScored(t, s, "C"); got.score != nil {
		t.Fatalf("C is not in the inventory; got %+v", got)
	}
}

func TestRescore_ClocksOnlyMoveWhenTheSeverityDid(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	ingestHigh(t, s, "customer-db", "B")
	var before time.Time
	s.DB.QueryRow(`SELECT remediation_due_date FROM tickets WHERE title = 'B'`).Scan(&before)
	s.UpsertAssets(ctx, []domain.Asset{{AssetIdentifier: "customer-db", Exposure: "internal", Criticality: "crown-jewel"}})
	s.RescoreAssets(ctx, []string{"customer-db"})
	var after time.Time
	s.DB.QueryRow(`SELECT remediation_due_date FROM tickets WHERE title = 'B'`).Scan(&after)
	if !after.Equal(before) {
		t.Fatalf("High stayed High: the clock must not move (%v -> %v)", before, after)
	}
}
