package datastore_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestFindingStructuredFields(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tk := &domain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, tk)

	err := store.UpdateFindingDetails(ctx, tk.ID, domain.FindingDetails{
		Severity: "Critical", Description: "reflected XSS in q param", Remediation: "encode output",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", CVSSScore: 9.1,
		CWE: "CWE-79", BusinessImpact: "Account takeover of any authenticated user",
	})
	if err != nil {
		t.Fatalf("UpdateFindingDetails: %v", err)
	}

	got, _ := store.GetTicketByID(ctx, tk.ID)
	if got.Severity != "Critical" || got.CVSSVector == "" || got.CVSSScore != 9.1 ||
		got.CWE != "CWE-79" || got.BusinessImpact == "" {
		t.Errorf("structured fields not persisted: %+v", got)
	}
}
