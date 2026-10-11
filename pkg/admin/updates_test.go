package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckUpdates_OfflineFallback(t *testing.T) {

	app, db := setupTestAdmin(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/check-updates", nil)
	req.AddCookie(GetVIPCookie(app.Store))
	rr := httptest.NewRecorder()

	app.HandleCheckUpdates(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, exists := response["status"]; !exists {
		t.Errorf("Expected 'status' field in response")
	}
	if _, exists := response["message"]; !exists {
		t.Errorf("Expected 'message' field in response")
	}
}
