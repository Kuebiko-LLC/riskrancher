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
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func setupTestTickets(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")
	store := datastore.NewSQLiteStore(db)
	return NewHandler(store), db
}

// GetVIPCookie creates a dummy Sheriff user and an active session,
func GetVIPCookie(store domain.Store) *http.Cookie {

	user, err := store.GetUserByEmail(context.Background(), "vip_test@RiskRancher.com")
	if err != nil {
		user, _ = store.CreateUser(context.Background(), "vip_test@RiskRancher.com", "Test VIP", "hash", "Sheriff")
	}

	token := "vip_test_token_999"
	store.CreateSession(context.Background(), token, user.ID, time.Now().Add(1*time.Hour))

	return &http.Cookie{
		Name:  "session_token",
		Value: token,
	}
}

func TestCreateSingleTicket(t *testing.T) {
	app, db := setupTestTickets(t)
	defer db.Close()

	payload := []byte(`{
		"title": "Manual Pentest Finding: XSS",
		"description": "Found reflected XSS on the search page.",
		"recommended_remediation": "Sanitize user input.",
		"severity": "High"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/api/tickets", bytes.NewBuffer(payload))
	req.AddCookie(GetVIPCookie(app.Store))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	app.HandleCreateTicket(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Fatalf("Expected status %v, got %v. Body: %s", http.StatusCreated, status, rr.Body.String())
	}

	var createdTicket domain.Ticket
	if err := json.NewDecoder(rr.Body).Decode(&createdTicket); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if createdTicket.ID == 0 {
		t.Errorf("Expected database to generate an ID")
	}
	if createdTicket.DedupeHash == "" {
		t.Errorf("Expected engine to generate a dedupe hash")
	}
}
