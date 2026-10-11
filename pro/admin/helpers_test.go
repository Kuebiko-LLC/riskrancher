// File: RiskRancher/pro/internal/admin/helpers_test.go
package admin

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	// 🚀 FIX: Split the imports into datastore (for DB) and domain (for core.Store)
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// setupTestAdmin spins up an in-memory database and the ProHandler for testing
func setupTestAdmin(t *testing.T) (*ProHandler, *sql.DB) {
	// 🚀 FIX: Call InitDB from the datastore package
	db := datastore.InitDB(":memory:")

	// 🚀 FIX: Inject the Enterprise Schema specifically for the tests.
	// We execute the DDL directly to avoid os.ReadFile relative path issues
	// during sub-package test execution.
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS auto_triage_rules (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   workspace_id INTEGER DEFAULT 1,
	   match_source TEXT,
	   match_asset TEXT,
	   match_cve TEXT,
	   action_type TEXT NOT NULL,
	   action_value TEXT NOT NULL,
	   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("🚨 PRO TEST FATAL: Failed to create test schema: %v", err)
	}

	// Initialize the Enterprise Database
	store := storage.NewProSQLiteStore(db)

	return NewProHandler(store), db
}

// GetVIPCookie creates a dummy Sheriff user and session so our HTTP tests bypass the Bouncer
func GetVIPCookie(store core.Store) *http.Cookie {
	ctx := context.Background()

	// Try to fetch or create the VIP user
	user, err := store.GetUserByEmail(ctx, "vip_test@riskrancher.com")
	if err != nil {
		user, _ = store.CreateUser(ctx, "vip_test@riskrancher.com", "Test VIP", "hash", "Sheriff")
	}

	// Generate a valid session token for them
	token := "vip_test_token_999"
	store.CreateSession(ctx, token, user.ID, time.Now().Add(1*time.Hour))

	return &http.Cookie{
		Name:  "session_token", // Ensure this matches your auth middleware's cookie name
		Value: token,
	}
}
