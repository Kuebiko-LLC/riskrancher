package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestAutoTriageRuleLifecycleBDD(t *testing.T) {
	// Setup the test application and database (using your helper from archive)
	app, db := setupTestAdmin(t)
	defer db.Close()

	// Convert the core.Store to ProStore so we can check the DB directly
	store := app.Store

	var createdRuleID int

	// =========================================================================
	// SCENARIO 1: Create a Triage Rule
	// =========================================================================
	t.Run("Given a Sheriff wants to automatically downgrade findings on a legacy asset", func(t *testing.T) {
		// WHEN they submit a POST request to create a Downgrade rule
		payload := domain.AutoTriageRule{
			MatchSource: "*",
			MatchAsset:  "legacy-api-server",
			MatchCVE:    "*",
			ActionType:  "DowngradeSeverity",
			ActionValue: "Low",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/triage", bytes.NewBuffer(body))

		// Bypass auth middleware for the test by injecting the VIP Sheriff cookie
		req.AddCookie(GetVIPCookie(app.Store))
		rr := httptest.NewRecorder()

		// Execute handler
		proHandler := NewHandler(app.Store)
		proHandler.HandleCreateTriageRule(rr, req)

		// THEN the API should return 201 Created
		if rr.Code != http.StatusCreated {
			t.Fatalf("Expected 201 Created, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		// AND the database should have assigned an ID
		var respRule domain.AutoTriageRule
		json.NewDecoder(rr.Body).Decode(&respRule)
		if respRule.ID == 0 {
			t.Fatalf("Expected a valid Database ID to be returned, got 0")
		}

		// Save ID for next scenarios
		createdRuleID = respRule.ID
	})

	// =========================================================================
	// SCENARIO 2: Fetch Active Triage Rules
	// =========================================================================
	t.Run("Given the Sheriff wants to view all active triage rules", func(t *testing.T) {
		// WHEN they submit a GET request to the triage endpoint
		req := httptest.NewRequest(http.MethodGet, "/api/admin/triage", nil)
		req.AddCookie(GetVIPCookie(app.Store))
		rr := httptest.NewRecorder()

		proHandler := NewHandler(app.Store)
		proHandler.HandleGetTriageRules(rr, req)

		// THEN the API should return 200 OK
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", rr.Code)
		}

		// AND the payload should contain the exact rule we just created
		var fetchedRules []domain.AutoTriageRule
		json.NewDecoder(rr.Body).Decode(&fetchedRules)

		if len(fetchedRules) != 1 {
			t.Fatalf("Expected 1 rule in the database, got %d", len(fetchedRules))
		}
		if fetchedRules[0].MatchAsset != "legacy-api-server" {
			t.Errorf("Expected Asset 'legacy-api-server', got %s", fetchedRules[0].MatchAsset)
		}
	})

	// =========================================================================
	// SCENARIO 3: Delete a Triage Rule
	// =========================================================================
	t.Run("Given the legacy server is decommissioned and the Sheriff deletes the rule", func(t *testing.T) {
		// WHEN they submit a DELETE request with the Rule ID
		targetURL := "/api/admin/triage/" + strconv.Itoa(createdRuleID)
		req := httptest.NewRequest(http.MethodDelete, targetURL, nil)

		// Mock the PathValue router injection for testing
		req.SetPathValue("id", strconv.Itoa(createdRuleID))
		req.AddCookie(GetVIPCookie(app.Store))
		rr := httptest.NewRecorder()

		proHandler := NewHandler(app.Store)
		proHandler.HandleDeleteTriageRule(rr, req)

		// THEN the API should return 200 OK
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", rr.Code)
		}

		// AND the rule should no longer exist in the database
		rules, _ := store.GetAutoTriageRules(context.Background())
		if len(rules) != 0 {
			t.Errorf("Expected 0 rules after deletion, but found %d", len(rules))
		}
	})
}
