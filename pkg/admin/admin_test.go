package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestGetGlobalConfig(t *testing.T) {
	app, db := setupTestAdmin(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.AddCookie(GetVIPCookie(app.Store))
	rr := httptest.NewRecorder()

	app.HandleGetConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var config domain.AppConfig
	if err := json.NewDecoder(rr.Body).Decode(&config); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if config.Timezone != "America/New_York" || config.BusinessStart != 9 {
		t.Errorf("Expected default config, got TZ: %s, Start: %d", config.Timezone, config.BusinessStart)
	}
}

func TestHandleDeactivateUser(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()

	targetUser, _ := h.Store.CreateUser(context.Background(), "fired@ranch.com", "Fired Fred", "hash", "RangeHand")
	res, _ := db.Exec(`INSERT INTO tickets (title, status, severity, source, dedupe_hash) VALUES ('Freds Task', 'Waiting to be Triaged', 'High', 'Manual', 'fake-hash-123')`)
	ticketID, _ := res.LastInsertId()
	db.Exec(`INSERT INTO ticket_assignments (ticket_id, assignee, role) VALUES (?, 'fired@ranch.com', 'RangeHand')`, ticketID)

	targetURL := fmt.Sprintf("/api/admin/users/%d", targetUser.ID)
	req := httptest.NewRequest(http.MethodDelete, targetURL, nil)
	req.AddCookie(GetVIPCookie(h.Store))
	req.SetPathValue("id", fmt.Sprintf("%d", targetUser.ID))
	rr := httptest.NewRecorder()

	h.HandleDeactivateUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM ticket_assignments WHERE assignee = 'fired@ranch.com'`).Scan(&count)
	if count != 0 {
		t.Errorf("Expected assignments to be cleared, but found %d", count)
	}
}
