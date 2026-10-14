package tickets

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	models "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// setupTestTickets spins up an in-memory database and the ProHandler for testing
func setupTestTickets(t *testing.T) (*ProHandler, *sql.DB) {
	db := datastore.InitDB(":memory:")

	// 🚀 FIX: Inject the Pro schema tables required by the Dashboard query
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS magic_batches (
		token TEXT PRIMARY KEY,
		created_by TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		is_revoked BOOLEAN DEFAULT 0,
		ticket_ids TEXT NOT NULL, 
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("Failed to create magic_batches table: %v", err)
	}

	// Initialize the store
	store := datastore.NewSQLiteStore(db)

	return NewProHandler(store), db
}

func TestWranglerReject_HTTP(t *testing.T) {
	app, db := setupTestTickets(t)
	defer db.Close()

	// 1. Arrange: Create a "Complete" ticket so rows.Scan() doesn't choke on NULLs
	ctx := context.Background()
	now := time.Now()
	ticket := models.Ticket{
		Source:          "Trivy",
		AssetIdentifier: "server-99",
		Title:           "Critical Vulnerability",
		Severity:        "Critical",
		DedupeHash:      "hash-http-99",
		Status:          "Assigned Out",
		Assignee:        "it-wrangler@ranch.com",
		// 🚀 FIX: Prevent NULL scan errors in GetDashboardTickets
		TriageDueDate:      now.Add(24 * time.Hour),
		RemediationDueDate: now.Add(7 * 24 * time.Hour),
		UpdatedAt:          now,
	}

	if err := app.Store.CreateTicket(ctx, &ticket); err != nil {
		t.Fatalf("Test Setup Failed: Could not create ticket: %v", err)
	}

	payload := map[string]interface{}{
		"ticket_ids": []int{ticket.ID},
		"reason":     "WRONG_OWNER",
		"comment":    "Transferred to Marketing.",
	}
	body, _ := json.Marshal(payload)

	// 2. Act: Send an HTTP Request to the Handler
	req := httptest.NewRequest(http.MethodPost, "/api/pro/tickets/reject", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "wrangler_mock_token"})

	w := httptest.NewRecorder()
	app.RejectTicketsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}

	// 3. Assert: Pure BDD! Read exactly how the UI reads it.
	tickets, _, _, err := app.Store.GetDashboardTickets(ctx, "holding_pen", "", "", "", "Sheriff", 10, 0)
	if err != nil {
		t.Fatalf("Failed to fetch dashboard tickets: %v", err)
	}

	found := false
	for _, tk := range tickets {
		if tk.ID == ticket.ID {
			found = true
			if tk.Status != "Returned to Security" {
				t.Errorf("Expected Dashboard status 'Returned to Security', got '%s'", tk.Status)
			}
		}
	}

	if !found {
		t.Errorf("Ticket not found in the holding pen via GetDashboardTickets")
	}
}
