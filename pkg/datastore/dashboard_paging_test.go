package datastore

import (
	"context"
	"fmt"
	"testing"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The Holding Pen pages by asset, not by row: a page holds whole asset groups,
// the pager counts assets, and a host with many findings never straddles pages.
func TestGetDashboardTickets_PagesByAsset(t *testing.T) {
	store := NewSQLiteStore(InitDB(":memory:"))
	defer store.DB.Close()

	// Given three assets with five open findings each
	for a := 0; a < 3; a++ {
		for i := 0; i < 5; i++ {
			_, err := store.DB.Exec(`INSERT INTO tickets (source, asset_identifier, title, severity, description, status, dedupe_hash, triage_due_date, remediation_due_date) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+3 days'), datetime('now', '+14 days'))`,
				"Scan", fmt.Sprintf("host-%d", a), fmt.Sprintf("finding %d", i), "High", "d", "Waiting to be Triaged", fmt.Sprintf("h-%d-%d", a, i))
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
	}

	// When the pen is read two assets per page
	page1, total, _, err := store.GetDashboardTickets(context.Background(), "holding_pen", "", "", "", "RangeHand", 2, 0)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	// Then the total counts assets, and page one holds every finding of exactly two assets
	if total != 3 {
		t.Fatalf("total should count assets (3), got %d", total)
	}
	if len(page1) != 10 {
		t.Fatalf("page 1 should hold 2 assets x 5 findings = 10, got %d", len(page1))
	}
	if n := distinctAssets(page1); n != 2 {
		t.Fatalf("page 1 should span exactly 2 assets, got %d", n)
	}

	// And page two holds the remaining asset, whole
	page2, _, _, err := store.GetDashboardTickets(context.Background(), "holding_pen", "", "", "", "RangeHand", 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2) != 5 || distinctAssets(page2) != 1 {
		t.Fatalf("page 2 should hold the last asset's 5 findings, got %d findings over %d assets", len(page2), distinctAssets(page2))
	}
}

func distinctAssets(ts []domain2.Ticket) int {
	seen := map[string]bool{}
	for _, t := range ts {
		seen[t.AssetIdentifier] = true
	}
	return len(seen)
}
