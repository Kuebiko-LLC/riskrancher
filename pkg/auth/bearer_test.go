package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// An API key acts as the user who created it and honors its own permissions.
func TestBearerKeyActsAsItsOwner(t *testing.T) {
	store := datastore.NewSQLiteStore(datastore.InitDB(":memory:"))
	defer store.DB.Close()
	ctx := context.Background()
	sheriff, err := store.CreateUser(ctx, "sheriff@rr.test", "Sheriff", "hash", "Sheriff")
	if err != nil {
		t.Fatal(err)
	}
	full, _ := store.CreateAPIKey(ctx, domain.APIKey{Name: "ci", Permissions: "FullAdmin", CreatedBy: sheriff.ID})
	readOnly, _ := store.CreateAPIKey(ctx, domain.APIKey{Name: "dash", Permissions: "ReadOnly", CreatedBy: sheriff.ID})
	past := time.Now().Add(-time.Hour)
	expired, _ := store.CreateAPIKey(ctx, domain.APIKey{Name: "old", Permissions: "FullAdmin", CreatedBy: sheriff.ID, ExpiresAt: &past})

	h := auth.NewHandler(store)
	sheriffOnly := h.RequireAuth(h.RequireRole("Sheriff")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	try := func(method, key string) int {
		req := httptest.NewRequest(method, "/api/admin/routing", nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		sheriffOnly.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := try(http.MethodPost, full); c != http.StatusOK {
		t.Fatalf("a full key owned by the Sheriff should pass a Sheriff-only route, got %d", c)
	}
	if c := try(http.MethodGet, readOnly); c != http.StatusOK {
		t.Fatalf("a read-only key should GET, got %d", c)
	}
	if c := try(http.MethodPost, readOnly); c != http.StatusForbidden {
		t.Fatalf("a read-only key must not write, got %d", c)
	}
	if c := try(http.MethodGet, expired); c != http.StatusUnauthorized {
		t.Fatalf("an expired key must be refused, got %d", c)
	}
	if c := try(http.MethodGet, "not-a-key"); c != http.StatusUnauthorized {
		t.Fatalf("an unknown key must be refused, got %d", c)
	}
	if c := try(http.MethodGet, ""); c != http.StatusUnauthorized {
		t.Fatalf("no credentials must be refused, got %d", c)
	}
}

// Deactivating a user ends their keys too.
func TestBearerKey_DeactivatedOwnerIsRejected(t *testing.T) {
	store := datastore.NewSQLiteStore(datastore.InitDB(":memory:"))
	defer store.DB.Close()
	ctx := context.Background()
	u, err := store.CreateUser(ctx, "leaver@rr.test", "Leaver", "hash", "Sheriff")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := store.CreateAPIKey(ctx, domain.APIKey{Name: "ci", Permissions: "FullAdmin", CreatedBy: u.ID})
	h := auth.NewHandler(store)
	guarded := h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	try := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/tickets", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := try(); c != http.StatusOK {
		t.Fatalf("an active owner's key works, got %d", c)
	}
	if err := store.DeactivateUserAndReassign(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if c := try(); c != http.StatusUnauthorized {
		t.Fatalf("a deactivated owner's key must stop, got %d", c)
	}
}
