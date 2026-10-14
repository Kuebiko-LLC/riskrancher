package storage_test

import (
	"context"
	"testing"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Findings being worked in an unreleased engagement must not appear in the
// RangeHand triage queue until the Bounty Hunter releases the engagement.
func TestUnreleasedEngagementFindingsHiddenFromQueue(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	inQueue := func() map[int]bool {
		rows, _, _, err := store.GetDashboardTickets(ctx, "holding_pen", "", "", "rh@ranch.com", "RangeHand", 100, 0)
		if err != nil {
			t.Fatalf("GetDashboardTickets: %v", err)
		}
		seen := map[int]bool{}
		for _, tk := range rows {
			seen[tk.ID] = true
		}
		return seen
	}

	// A normal scanner finding is visible immediately.
	normal := &coredomain.Ticket{Source: "Trivy", AssetIdentifier: "host", Title: "normal", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, normal)
	if !inQueue()[normal.ID] {
		t.Fatalf("a normal finding should be in the RangeHand queue")
	}

	// A BH engagement finding is hidden while the engagement is Active.
	eng := &coredomain.Engagement{Name: "Pentest", Client: "Acme", OwnerEmail: "bh@ranch.com"}
	store.CreateEngagement(ctx, eng)
	finding := &coredomain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "Critical", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, finding)
	store.AddFindingsToEngagement(ctx, eng.ID, []int{finding.ID})

	if inQueue()[finding.ID] {
		t.Errorf("an unreleased engagement finding must be hidden from the RangeHand queue")
	}
	if !inQueue()[normal.ID] {
		t.Errorf("the normal finding should still be visible")
	}

	// Releasing the engagement hands the finding off to the queue.
	store.ReleaseEngagement(ctx, eng.ID)
	if !inQueue()[finding.ID] {
		t.Errorf("after release the engagement finding must appear in the queue")
	}
}
