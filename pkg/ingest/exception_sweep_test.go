package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Every upload starts with the expiry sweep, so an accepted risk whose date
// has passed is back on the queue before the new scan is diffed.
func TestIngest_SweepsExpiredExceptionsFirst(t *testing.T) {
	h, db := setupTestIngest(t)
	defer db.Close()
	ctx := context.Background()
	tk := domain.Ticket{Source: "Nessus", AssetIdentifier: "legacy-billing", Title: "TLS 1.0 enabled", Severity: "High", Domain: "Vulnerability"}
	if err := h.Store.CreateTicket(ctx, &tk); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.RequestRiskException(ctx, []int{tk.ID}, "Risk Acceptance", "refactor", "finance@rr.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.ReviewRiskRequest(ctx, []int{tk.ID}, "Approve", "cfo@rr.test", "signed", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE tickets SET exception_expires_at = DATETIME('now', '-1 day') WHERE id = ?`, tk.ID); err != nil {
		t.Fatal(err)
	}

	// A scan from another source on another asset: unrelated to the finding
	body := `[{"source":"Trivy","asset_identifier":"img","title":"CVE-0000-0009","severity":"Low"}]`
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleIngest(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := h.Store.GetTicketByID(ctx, tk.ID)
	if got.Status != "Waiting to be Triaged" {
		t.Fatalf("the upload must sweep expired exceptions first, got %q", got.Status)
	}
}
