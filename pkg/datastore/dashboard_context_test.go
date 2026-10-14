package datastore_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The queue says what the asset is and how the priority was reached, so a
// person reading a Critical can see the scanner's word and the arithmetic.
func TestGetDashboardTicketsWithPortals_CarriesAssetContext(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	ingestHigh(t, s, "payments-api", "Known asset finding")
	ingestHigh(t, s, "mystery-box", "Unknown asset finding")

	tickets, _, _, err := s.GetDashboardTicketsWithPortals(ctx, "holding_pen", "", "", "sheriff@rr.test", "Sheriff", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	byTitle := map[string]domain.DashboardTicket{}
	for _, tk := range tickets {
		byTitle[tk.Title] = tk
	}
	known := byTitle["Known asset finding"]
	if known.AssetExposure != "internet" || known.AssetCriticality != "crown-jewel" || known.ScannerSeverity != "High" {
		t.Fatalf("known asset context: %+v", known)
	}
	if known.ContextLine != "Scanner said High. internet x crown-jewel, score 12." {
		t.Fatalf("context line: %q", known.ContextLine)
	}
	unknown := byTitle["Unknown asset finding"]
	if unknown.AssetExposure != "" || unknown.ContextLine != "Scanner said High. Asset not in the inventory." {
		t.Fatalf("unknown asset context: %+v", unknown)
	}
}

func TestContextLine_NamesWhatDecidedIt(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	paymentsAPI(t, s)
	s.DB.Exec(`INSERT INTO auto_triage_rules (match_asset, action_type, action_value) VALUES ('payments-api', 'DowngradeSeverity', 'Low')`)
	ingestHigh(t, s, "payments-api", "Ruled finding")
	tickets, _, _, _ := s.GetDashboardTicketsWithPortals(ctx, "holding_pen", "", "", "", "Sheriff", 10, 0)
	if len(tickets) != 1 || tickets[0].ContextLine != "Scanner said High. internet x crown-jewel, score 12. Severity rule: Low." {
		t.Fatalf("rule named: %+v", tickets)
	}
	s.DB.Exec(`UPDATE tickets SET is_cisa_kev = 1, severity = 'Critical'`)
	tickets, _, _, _ = s.GetDashboardTicketsWithPortals(ctx, "holding_pen", "", "", "", "Sheriff", 10, 0)
	if tickets[0].ContextLine != "Scanner said High. internet x crown-jewel, score 12. Known exploited: Critical." {
		t.Fatalf("KEV named: %q", tickets[0].ContextLine)
	}
}
