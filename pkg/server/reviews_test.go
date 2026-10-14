package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The Risk Reviews tab shows what the owner asked for and why, not the
// finding's description, and the approver's page starts from the
// configured default extension days.
func TestAdminReviewsShowTheRequest(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "payments-api", Title: "CVE-0000-0001 review", Description: "scanner text nobody asked about", Severity: "High", Domain: "Vulnerability",
		TriageDueDate: time.Now().Add(72 * time.Hour), RemediationDueDate: time.Now().Add(720 * time.Hour)}
	if err := app.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	token, err := app.Store.BulkUpdateStatusAndAssign(ctx, []int{tk.ID}, "Assigned Out", "dana@rr.test", "", "sheriff@rr.test")
	if err != nil || token == "" {
		t.Fatal(err)
	}
	if err := app.Store.RequestRiskException(ctx, []int{tk.ID}, "Time Extension", "sprint lands late", "dana@rr.test"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin page: %d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, "sprint lands late") {
		t.Fatalf("Risk Reviews must show the owner's rationale")
	}
	if !strings.Contains(page, "Time Extension") {
		t.Fatalf("Risk Reviews must label the kind of request")
	}
	if strings.Contains(page, "scanner text nobody asked about") || strings.Contains(page, "SLA Paused") {
		t.Fatalf("Risk Reviews must not show the description as the justification or claim the clock is paused")
	}

	// The approver's page learns the default from configuration
	req = httptest.NewRequest(http.MethodGet, "/api/share/"+token, nil)
	rec = httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	var payload struct {
		DefaultExtensionDays int `json:"default_extension_days"`
	}
	json.Unmarshal(rec.Body.Bytes(), &payload)
	if payload.DefaultExtensionDays != 30 {
		t.Fatalf("portal payload must carry the configured default extension days (30 by default), got %d", payload.DefaultExtensionDays)
	}
	src, _ := fsReadUI("static/magic.js")
	if !strings.Contains(src, "default_extension_days") {
		t.Fatalf("the approver page must set its days field from the payload")
	}
}
