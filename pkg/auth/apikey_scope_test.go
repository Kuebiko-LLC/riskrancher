package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// An Ingest key acts as its Sheriff creator for ownership, but may reach ONLY the ingest
// endpoints. A leaked scanner key must not touch user, config or key-management routes.
func TestIngestKeyIsScopedToIngest(t *testing.T) {
	store := datastore.NewSQLiteStore(datastore.InitDB(":memory:"))
	defer store.DB.Close()
	ctx := context.Background()
	sheriff, err := store.CreateUser(ctx, "sheriff@rr.test", "Sheriff", "hash", "Sheriff")
	if err != nil {
		t.Fatal(err)
	}
	ingest, _ := store.CreateAPIKey(ctx, domain.APIKey{Name: "scanner", Permissions: "Ingest", CreatedBy: sheriff.ID})

	h := auth.NewHandler(store)
	guarded := h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	try := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+ingest)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec.Code
	}

	// Allowed: POST to any ingest path.
	if c := try(http.MethodPost, "/api/ingest"); c != http.StatusOK {
		t.Errorf("POST /api/ingest with an Ingest key = %d, want 200", c)
	}
	if c := try(http.MethodPost, "/api/ingest/csv"); c != http.StatusOK {
		t.Errorf("POST /api/ingest/csv with an Ingest key = %d, want 200", c)
	}
	// Forbidden: anything else, including a GET on ingest and any admin route.
	if c := try(http.MethodGet, "/api/tickets"); c != http.StatusForbidden {
		t.Errorf("GET /api/tickets with an Ingest key = %d, want 403", c)
	}
	if c := try(http.MethodPost, "/api/admin/apikeys"); c != http.StatusForbidden {
		t.Errorf("POST /api/admin/apikeys with an Ingest key = %d, want 403", c)
	}
	if c := try(http.MethodGet, "/api/ingest"); c != http.StatusForbidden {
		t.Errorf("GET /api/ingest (wrong method) with an Ingest key = %d, want 403", c)
	}
}
