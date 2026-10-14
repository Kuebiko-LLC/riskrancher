// File: RiskRancher/pro/storage/api_keys_test.go
package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	// Add this line below:
	core "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func TestAPIKeys_BDD(t *testing.T) {
	db := core.InitDB(":memory:")
	defer db.Close()

	// Disable foreign-key enforcement to test the API key logic in isolation
	// without needing to perfectly mock the free tier's Users and Workspaces tables.
	_, _ = db.Exec("PRAGMA foreign_keys = OFF;")

	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)
	ctx := context.Background()

	t.Run("Given an admin wants to create a Service Account", func(t *testing.T) {
		req := models.APIKey{
			WorkspaceID: 1,
			Name:        "CI/CD Pipeline Key",
			Permissions: "WriteOnly",
			CreatedBy:   1, // Will no longer trip the FK constraint
		}

		var rawToken string

		t.Run("When the key is generated", func(t *testing.T) {
			var err error
			rawToken, err = store.CreateAPIKey(ctx, req)
			if err != nil {
				t.Fatalf("Failed to create API key: %v", err)
			}
			if len(rawToken) < 32 {
				t.Errorf("Expected raw token to be at least 32 chars long, got %d", len(rawToken))
			}
		})

		t.Run("Then the database should only contain the hash, not the raw token", func(t *testing.T) {
			hashBytes := sha256.Sum256([]byte(rawToken))
			expectedHash := hex.EncodeToString(hashBytes[:])

			keyRecord, err := store.GetAPIKeyByHash(ctx, expectedHash)
			if err != nil {
				t.Fatalf("Failed to retrieve key by hash: %v", err)
			}

			if keyRecord.Name != "CI/CD Pipeline Key" {
				t.Errorf("Expected name 'CI/CD Pipeline Key', got '%s'", keyRecord.Name)
			}
			if keyRecord.Permissions != "WriteOnly" {
				t.Errorf("Expected permissions 'WriteOnly', got '%s'", keyRecord.Permissions)
			}
		})
	})
}
