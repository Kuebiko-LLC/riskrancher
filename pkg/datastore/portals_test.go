package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// An approval with no days given uses the configured default, not a number
// baked into the code.
func TestReviewRiskRequest_DefaultDaysComeFromConfig(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 days", Severity: "High", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE app_config SET default_extension_days = 21 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestRiskException(ctx, []int{tk.ID}, "Time Extension", "need three weeks", "dana@rr.test"); err != nil {
		t.Fatal(err)
	}
	before, _ := s.GetTicketByID(ctx, tk.ID)
	if err := s.ReviewRiskRequest(ctx, []int{tk.ID}, "Approve", "approver@rr.test", "ok", 0); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetTicketByID(ctx, tk.ID)
	if moved := int(after.RemediationDueDate.Sub(before.RemediationDueDate).Hours()/24 + 0.5); moved != 21 {
		t.Fatalf("approval with no days must use the configured 21, moved %d", moved)
	}
}
