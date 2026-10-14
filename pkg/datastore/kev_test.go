package datastore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// A KEV sync flags every open finding that names a catalog CVE in its title
// or description, in any letter case, and unflags findings whose CVE left
// the catalog. Findings without a CVE are untouched.
func TestSyncCISACatalog_FlagsByCVEInTitleOrDescription(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	mk := func(title, desc string) int {
		tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "host-" + title, Title: title, Description: desc, Severity: "High", Domain: "Vulnerability",
			TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
		if err := s.CreateTicket(ctx, &tk); err != nil {
			t.Fatal(err)
		}
		return tk.ID
	}
	inTitle := mk("CVE-2021-44228 Log4Shell", "")
	inDesc := mk("Apache Log4j2 RCE", "Scanner matched cve-2021-44228 on the host.")
	other := mk("CVE-2016-2107 OpenSSL", "")
	none := mk("Missing headers", "no cve here")

	feed := func(cves ...string) *domain.CISAFeed {
		var f domain.CISAFeed
		raw := `{"vulnerabilities":[`
		for i, c := range cves {
			if i > 0 {
				raw += ","
			}
			raw += `{"cveID":"` + c + `","dateAdded":"2024-01-01"}`
		}
		json.Unmarshal([]byte(raw+`]}`), &f)
		return &f
	}
	flagged := func(id int) bool {
		var v bool
		s.DB.QueryRow(`SELECT is_cisa_kev FROM tickets WHERE id = ?`, id).Scan(&v)
		return v
	}

	if _, err := s.SyncCISACatalog(ctx, feed("CVE-2021-44228")); err != nil {
		t.Fatal(err)
	}
	if !flagged(inTitle) || !flagged(inDesc) || flagged(other) || flagged(none) {
		t.Fatalf("first sync: title=%v desc=%v other=%v none=%v", flagged(inTitle), flagged(inDesc), flagged(other), flagged(none))
	}

	// The catalog moves on: a new CVE lands, the old one is dropped
	if _, err := s.SyncCISACatalog(ctx, feed("CVE-2016-2107")); err != nil {
		t.Fatal(err)
	}
	if flagged(inTitle) || flagged(inDesc) || !flagged(other) || flagged(none) {
		t.Fatalf("second sync: title=%v desc=%v other=%v none=%v", flagged(inTitle), flagged(inDesc), flagged(other), flagged(none))
	}
}
