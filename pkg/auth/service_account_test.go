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

func TestServiceAccountAuth_BDD(t *testing.T) {
	// 1. Setup In-Memory DB and Store
	db := datastore.InitDB(":memory:")
	defer db.Close()

	// Disable FKs so we don't have to mock the entire Core User/Workspace tables
	_, _ = db.Exec("PRAGMA foreign_keys = OFF;")
	store := datastore.NewSQLiteStore(db)

	// 2. Mint a valid API Key for testing
	validAPIKeyReq := domain.APIKey{
		WorkspaceID: 1,
		Name:        "CI/CD Pipeline Key",
		Permissions: "WriteOnly",
		CreatedBy:   99, // Arbitrary User ID
	}
	rawToken, err := store.CreateAPIKey(context.Background(), validAPIKeyReq)
	if err != nil {
		t.Fatalf("Failed to seed test API key: %v", err)
	}

	// 3. Setup the Middleware and a Dummy Target Handler
	authMiddleware := auth.ServiceAccountAuth(store)

	// This dummy handler just checks if the middleware successfully injected the context
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isSA := r.Context().Value("is_service_account")
		if isSA != nil && isSA.(bool) == true {
			role := r.Context().Value("role").(string)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome Service Account. Role: " + role))
			return
		}

		// If no Service Account context, assume it's a normal Web UI request
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome Normal User"))
	})

	// Wrap the handler
	protectedRoute := authMiddleware(targetHandler)

	// --- THE BDD TESTS ---

	t.Run("Given a request from a normal Web UI user", func(t *testing.T) {
		t.Run("When they provide NO Authorization header", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/tickets", nil)
			rr := httptest.NewRecorder()

			protectedRoute.ServeHTTP(rr, req)

			t.Run("Then it passes through to normal auth and returns 200 OK", func(t *testing.T) {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected 200 OK, got %d", rr.Code)
				}
				if rr.Body.String() != "Welcome Normal User" {
					t.Errorf("Expected Normal User access, got: %s", rr.Body.String())
				}
			})
		})
	})

	t.Run("Given an attacker or misconfigured script", func(t *testing.T) {
		t.Run("When they provide an INVALID or revoked Bearer token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/tickets", nil)
			req.Header.Set("Authorization", "Bearer totally-fake-token-12345")
			rr := httptest.NewRecorder()

			protectedRoute.ServeHTTP(rr, req)

			t.Run("Then it immediately rejects them with 401 Unauthorized", func(t *testing.T) {
				if rr.Code != http.StatusUnauthorized {
					t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
				}
			})
		})
	})

	t.Run("Given an automated CI/CD pipeline", func(t *testing.T) {
		t.Run("When it provides the VALID raw Bearer token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/tickets", nil)
			req.Header.Set("Authorization", "Bearer "+rawToken)
			rr := httptest.NewRecorder()

			protectedRoute.ServeHTTP(rr, req)

			t.Run("Then it returns 200 OK and injects the Service Account Identity into the context", func(t *testing.T) {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected 200 OK, got %d", rr.Code)
				}
				if rr.Body.String() != "Welcome Service Account. Role: WriteOnly" {
					t.Errorf("Expected Service Account context injection, got: %s", rr.Body.String())
				}
			})
		})
	})
}
