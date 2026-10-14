package datastore_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Findings held inside an unreleased engagement are not on the ranch yet:
// the metrics page does not count them.
func TestAnalytics_IgnoreHeldFindings(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	tk := domain.Ticket{Source: "Manual Pentest", AssetIdentifier: "client-app", Title: "CVE-2021-44228 held", Severity: "Critical", Domain: "Vulnerability"}
	if err := s.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE tickets SET released = 0, is_cisa_kev = 1, remediation_due_date = DATETIME('now', '-1 day') WHERE id = ?`, tk.ID); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetSheriffAnalytics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.OpenCriticals != 0 || m.ActiveKEVs != 0 || m.TotalOverdue != 0 || m.Severity.Total != 0 || len(m.TopAssets) != 0 || len(m.SourceHealth) != 0 {
		t.Fatalf("held findings counted: criticals=%d kevs=%d overdue=%d sev=%d assets=%d sources=%d", m.OpenCriticals, m.ActiveKEVs, m.TotalOverdue, m.Severity.Total, len(m.TopAssets), len(m.SourceHealth))
	}
	sum, _ := s.GetAnalyticsSummary(ctx)
	if sum["Total_Open"] != 0 {
		t.Fatalf("summary counted a held finding: %v", sum)
	}
}
