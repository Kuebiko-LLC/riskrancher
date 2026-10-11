package analytics

import (
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

func setupTestAnalytics(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")
	store := datastore.NewSQLiteStore(db)
	return NewHandler(store), db
}

func GetVIPCookie(store domain.Store) *http.Cookie {
	user, _ := store.CreateUser(context.Background(), "vip@RiskRancher.com", "Test VIP", "hash", "Sheriff")
	store.CreateSession(context.Background(), "vip_token_999", user.ID, time.Now().Add(1*time.Hour))
	return &http.Cookie{Name: "session_token", Value: "vip_token_999"}
}

func TestAnalyticsSummary(t *testing.T) {
	h, db := setupTestAnalytics(t)
	defer db.Close()

	_, err := db.Exec(`INSERT INTO tickets (source, title, severity, status, dedupe_hash) VALUES 
		('Trivy', 'Container CVE', 'Critical', 'Waiting to be Triaged', 'hash1'),
		('Trivy', 'Old Lib', 'High', 'Waiting to be Triaged', 'hash2'),
		('Trivy', 'Patched Lib', 'Critical', 'Patched', 'hash3'),
		('Manual Pentest', 'SQLi', 'Critical', 'Waiting to be Triaged', 'hash4')
	`)
	if err != nil {
		t.Fatalf("Failed to insert dummy data: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/summary", nil)
	req.AddCookie(GetVIPCookie(h.Store))
	rr := httptest.NewRecorder()

	h.HandleGetAnalyticsSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var summary map[string]int
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if summary["Total_Open"] != 3 {
		t.Errorf("Expected 3 total open tickets, got %d", summary["Total_Open"])
	}
}
