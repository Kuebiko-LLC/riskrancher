package datastore_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Promoted pentest findings land in the same engine as scanner findings:
// a logged false positive closes them, the SLA matrix sets their clock,
// and a routing rule hands them to the owner.
func TestPromotePentestDrafts_RunsTheRulesAndTheMatrix(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	if err := s.CreateSuppressionRule(ctx, &domain.SuppressionRule{DedupeHash: hashOf("Manual Pentest", "marketing-site", "SQL Injection (possible)"), AssetIdentifier: "marketing-site", Rationale: "static site", Actor: "sheriff@rr.test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRoutingRule(ctx, &domain.RoutingRule{RuleType: "Asset", MatchValue: "payments-api", Assignee: "dana@rr.test", Role: "Wrangler"}); err != nil {
		t.Fatal(err)
	}
	drafts := []domain.Ticket{
		{AssetIdentifier: "marketing-site", Title: "SQL Injection (possible)", Severity: "High", Description: "scanner echo"},
		{AssetIdentifier: "payments-api", Title: "IDOR on /orders", Severity: "critical", Description: "any order id readable", RecommendedRemediation: "authorize by owner"},
	}
	if err := s.PromotePentestDrafts(ctx, "report-1", "tester@rr.test", drafts); err != nil {
		t.Fatal(err)
	}
	status, _, _ := ticketStatus(t, s, hashOf("Manual Pentest", "marketing-site", "SQL Injection (possible)"))
	if status != "False Positive" {
		t.Fatalf("a logged false positive closes the promoted finding, got %q", status)
	}
	status, severity, assignee := ticketStatus(t, s, hashOf("Manual Pentest", "payments-api", "IDOR on /orders"))
	if status != "Assigned Out" || assignee != "dana@rr.test" || severity != "Critical" {
		t.Fatalf("routed and normalized: status=%q assignee=%q severity=%q", status, assignee, severity)
	}
	var due time.Time
	var source string
	s.DB.QueryRow(`SELECT remediation_due_date, source FROM tickets WHERE title = 'IDOR on /orders'`).Scan(&due, &source)
	if days := int(time.Until(due).Hours()/24 + 0.5); days != 14 || source != "Manual Pentest" {
		t.Fatalf("a Critical pentest finding gets the matrix clock of 14 days from source Manual Pentest, got %d days, source %q", days, source)
	}
	var analystRows, drafted int
	s.DB.QueryRow(`SELECT COUNT(*) FROM ticket_assignments WHERE assignee = 'tester@rr.test' AND role = 'RangeHand'`).Scan(&analystRows)
	s.DB.QueryRow(`SELECT COUNT(*) FROM draft_tickets WHERE report_id = 'report-1'`).Scan(&drafted)
	if analystRows != 2 || drafted != 0 {
		t.Fatalf("the analyst stays on both findings and the drafts are consumed: analyst rows=%d drafts=%d", analystRows, drafted)
	}
}
