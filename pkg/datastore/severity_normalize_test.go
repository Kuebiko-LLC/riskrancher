package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Scanners spell severity their own way. The store keeps one spelling, so
// the SLA matrix and every count see the same Critical.
func TestIngest_NormalizesSeverityCase(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	batch := []domain.Ticket{
		{Source: "Trivy", AssetIdentifier: "img", Title: "CVE-0000-0001 upper", Severity: "CRITICAL"},
		{Source: "Trivy", AssetIdentifier: "img", Title: "CVE-0000-0002 lower", Severity: "critical"},
		{Source: "Trivy", AssetIdentifier: "img", Title: "CVE-0000-0003 info", Severity: "Informational"},
	}
	if err := s.ProcessIngestionBatch(ctx, "Trivy", "img", batch); err != nil {
		t.Fatal(err)
	}
	for title, want := range map[string]string{"CVE-0000-0001 upper": "Critical", "CVE-0000-0002 lower": "Critical", "CVE-0000-0003 info": "Info"} {
		var sev string
		var due time.Time
		s.DB.QueryRow(`SELECT severity, remediation_due_date FROM tickets WHERE title = ?`, title).Scan(&sev, &due)
		if sev != want {
			t.Fatalf("%s: stored severity %q, want %q", title, sev, want)
		}
		if want == "Critical" {
			if days := int(time.Until(due).Hours()/24 + 0.5); days != 14 {
				t.Fatalf("%s: a Critical gets the matrix clock of 14 days, got %d", title, days)
			}
		}
	}
	// The single-create path and the drawer edit normalize too
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "h", Title: "single", Severity: "HIGH", Domain: "Vulnerability"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTicketByID(ctx, tk.ID)
	if got.Severity != "High" {
		t.Fatalf("CreateTicket must normalize, got %q", got.Severity)
	}
	if err := s.UpdateTicketInline(ctx, tk.ID, "medium", "", "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTicketByID(ctx, tk.ID)
	if got.Severity != "Medium" {
		t.Fatalf("drawer edit must normalize, got %q", got.Severity)
	}
}
