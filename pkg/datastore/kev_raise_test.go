package datastore_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Loading a catalog raises every open finding it newly flags to Critical and
// restarts its clock; closed findings and findings it does not name are
// untouched; loading the same catalog again raises nothing.
func TestSyncCISACatalog_RaisesNewlyFlaggedOpenFindings(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	batch := []domain.Ticket{
		{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-2021-44228 open", Severity: "High"},
		{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-2021-44228 patched", Severity: "High"},
		{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Plain finding", Severity: "Medium"},
	}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(`UPDATE tickets SET status = 'Patched' WHERE title = 'CVE-2021-44228 patched'`)
	s.DB.Exec(`UPDATE tickets SET created_at = datetime('now', '-10 days')`)

	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`), &feed)
	raised, err := s.SyncCISACatalog(ctx, &feed)
	if err != nil {
		t.Fatal(err)
	}
	if raised != 1 {
		t.Fatalf("one open finding raised, got %d", raised)
	}
	open := readScored(t, s, "CVE-2021-44228 open")
	if open.severity != "Critical" || !open.kev || open.scanner != "High" {
		t.Fatalf("open flagged finding is Critical now; got %+v", open)
	}
	if d := daysUntil(open.due); d != 4 {
		t.Fatalf("clock from created_at: 10 days ago + 14 = 4 left, got %d", d)
	}
	if activityCount(t, s, "CVE-2021-44228 open", "rescored") != 1 {
		t.Fatal("the raise is on the record")
	}
	if got := readScored(t, s, "CVE-2021-44228 patched"); got.severity != "High" || !got.kev {
		t.Fatalf("patched finding is flagged but not raised; got %+v", got)
	}
	if got := readScored(t, s, "Plain finding"); got.severity != "Medium" || got.kev {
		t.Fatalf("unrelated finding untouched; got %+v", got)
	}
	if raised, _ := s.SyncCISACatalog(ctx, &feed); raised != 0 {
		t.Fatalf("same catalog again raises nothing, got %d", raised)
	}
}
