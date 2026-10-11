package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestExportSystemState(t *testing.T) {
	app, db := setupTestAdmin(t)
	defer db.Close()
	_, err := db.Exec(`
		INSERT INTO tickets (title, severity, status, dedupe_hash) 
		VALUES ('Export Test Vuln', 'High', 'Triaged', 'test_hash_123')
	`)
	if err != nil {
		t.Fatalf("Failed to insert test ticket: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/export", nil)
	req.AddCookie(GetVIPCookie(app.Store))
	rr := httptest.NewRecorder()

	app.HandleExportState(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Disposition") != "attachment; filename=RiskRancher_export.json" {
		t.Errorf("Missing or incorrect Content-Disposition header")
	}

	var state domain.ExportState
	if err := json.NewDecoder(rr.Body).Decode(&state); err != nil {
		t.Fatalf("Failed to decode exported JSON: %v", err)
	}

	if len(state.Tickets) == 0 || state.Tickets[0].Title != "Export Test Vuln" {
		t.Errorf("Export did not contain the expected ticket data")
	}
}
