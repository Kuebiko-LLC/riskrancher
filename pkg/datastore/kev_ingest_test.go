package datastore_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Once a catalog is loaded, a finding that names one of its CVEs is flagged
// as it lands, not at the next sync.
func TestIngest_FlagsKEVAtInsert(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	var feed domain.CISAFeed
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}`), &feed)
	if _, err := s.SyncCISACatalog(ctx, &feed); err != nil {
		t.Fatal(err)
	}
	batch := []domain.Ticket{
		{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Apache Log4j2 RCE", Description: "matches cve-2021-44228 on the host", Severity: "Critical"},
		{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Missing headers", Severity: "Low"},
	}
	if err := s.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	flagged := func(title string) bool {
		var v bool
		s.DB.QueryRow(`SELECT is_cisa_kev FROM tickets WHERE title = ?`, title).Scan(&v)
		return v
	}
	if !flagged("Apache Log4j2 RCE") || flagged("Missing headers") {
		t.Fatalf("flag at insert: log4j=%v headers=%v", flagged("Apache Log4j2 RCE"), flagged("Missing headers"))
	}
	// The single-create path too
	tk := domain.Ticket{Source: "Trivy", AssetIdentifier: "img", Title: "CVE-2021-44228 in image", Severity: "Critical", Domain: "Vulnerability"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if !flagged("CVE-2021-44228 in image") {
		t.Fatalf("CreateTicket must flag a catalog CVE")
	}
	// Loading a catalog that dropped the CVE unflags both
	json.Unmarshal([]byte(`{"vulnerabilities":[{"cveID":"CVE-2014-0160","dateAdded":"2022-05-04"}]}`), &feed)
	if _, err := s.SyncCISACatalog(ctx, &feed); err != nil {
		t.Fatal(err)
	}
	if flagged("Apache Log4j2 RCE") || flagged("CVE-2021-44228 in image") {
		t.Fatalf("a sync without the CVE must unflag")
	}
}
