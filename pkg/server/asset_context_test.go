package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The Holding Pen carries each asset's exposure and criticality and each
// finding's context line, so the page can show them without another call.
func TestDashboardShowsAssetContext(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	ctx := context.Background()
	if err := app.Store.UpsertAssets(ctx, []domain.Asset{{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel"}}); err != nil {
		t.Fatal(err)
	}
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Outdated OpenSSL", Severity: "High", Domain: "Vulnerability"}
	if err := app.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard?tab=holding_pen", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`data-exposure="internet"`, `data-criticality="crown-jewel"`, `id="ctx-`, "Scanner said High. internet x crown-jewel, score 12.", `id="drawerContext"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %q", want)
		}
	}
}
