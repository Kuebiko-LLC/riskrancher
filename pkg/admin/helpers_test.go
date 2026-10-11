package admin

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// setupTestAdmin returns the clean Admin Handler and the raw DB
func setupTestAdmin(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")
	store := datastore.NewSQLiteStore(db)
	return NewHandler(store), db
}

// GetVIPCookie creates a dummy Sheriff user to bypass the Bouncer in tests
func GetVIPCookie(store domain.Store) *http.Cookie {
	user, err := store.GetUserByEmail(context.Background(), "vip_test@RiskRancher.com")
	if err != nil {
		user, _ = store.CreateUser(context.Background(), "vip_test@RiskRancher.com", "Test VIP", "hash", "Sheriff")
	}
	token := "vip_test_token_999"
	store.CreateSession(context.Background(), token, user.ID, time.Now().Add(1*time.Hour))
	return &http.Cookie{Name: "session_token", Value: token}
}
