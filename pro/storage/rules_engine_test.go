// File: RiskRancher/pro/storage/rules_engine_test.go
package storage_test

import (
	"context"
	"testing"
	"time"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	models "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func setupTestDB(t *testing.T) *storage.ProSQLiteStore {
	db := core.InitDB(":memory:")

	_, err := db.Exec("CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, name TEXT)")
	if err != nil {
		t.Fatalf("Failed to mock workspaces table: %v", err)
	}

	_, err = db.Exec("INSERT OR IGNORE INTO workspaces (id, name) VALUES (1, 'Global')")
	if err != nil {
		t.Fatalf("Failed to insert workspace: %v", err)
	}

	storage.InjectProSchema(db)

	return storage.NewProSQLiteStore(db)
}

func TestRulesEngine_BDD(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("Given a Global Suppression Rule, When a matching ticket is ingested, Then it is immediately marked as False Positive", func(t *testing.T) {
		store := setupTestDB(t)

		// 1. Arrange
		suppressionRule := &proModels.SuppressionRule{
			DedupeHash:      "hash-123",
			AssetIdentifier: "server-01",
			Rationale:       "Test FP",
			Actor:           "admin",
		}

		if err := store.CreateSuppressionRule(ctx, suppressionRule); err != nil {
			t.Fatalf("Arrange Failed - Could not create suppression rule: %v", err)
		}

		ticket := &models.Ticket{
			Source:             "Trivy",
			AssetIdentifier:    "server-01",
			Severity:           "High",
			DedupeHash:         "hash-123",
			Title:              "Test Vuln",
			Status:             "Waiting to be Triaged", // 🚀 FIX: Valid DB Status
			TriageDueDate:      now.Add(24 * time.Hour),
			RemediationDueDate: now.Add(7 * 24 * time.Hour),
		}

		// 2. Act
		if err := store.CreateTicket(ctx, ticket); err != nil {
			t.Fatalf("Act Failed - Could not create ticket: %v", err)
		}

		// 3. Assert
		if ticket.Status != "False Positive" {
			t.Errorf("Expected status to be 'False Positive', got '%s'", ticket.Status)
		}
	})

	t.Run("Given an Auto-Triage Rule, When a matching ticket is ingested, Then its severity is automatically downgraded", func(t *testing.T) {
		store := setupTestDB(t)

		// 1. Arrange
		triageRule := &proModels.AutoTriageRule{
			WorkspaceID: 1,
			MatchSource: "Trivy",
			MatchAsset:  "legacy-app",
			ActionType:  "DowngradeSeverity",
			ActionValue: "Low",
		}
		if err := store.CreateAutoTriageRule(ctx, triageRule); err != nil {
			t.Fatalf("Arrange Failed - Could not create triage rule: %v", err)
		}

		ticket := &models.Ticket{
			Source:             "Trivy",
			AssetIdentifier:    "legacy-app",
			Severity:           "Critical",
			DedupeHash:         "hash-456",
			Title:              "Test Vuln",
			Status:             "Waiting to be Triaged", // 🚀 FIX: Valid DB Status
			TriageDueDate:      now.Add(24 * time.Hour),
			RemediationDueDate: now.Add(7 * 24 * time.Hour),
		}

		// 2. Act
		if err := store.CreateTicket(ctx, ticket); err != nil {
			t.Fatalf("Act Failed - Could not create ticket: %v", err)
		}

		// 3. Assert
		if ticket.Severity != "Low" {
			t.Errorf("Expected severity to be downgraded to 'Low', got '%s'", ticket.Severity)
		}
	})

	t.Run("Given a Routing Rule, When a matching ticket is ingested, Then it is assigned out and bypasses the Holding Pen", func(t *testing.T) {
		store := setupTestDB(t)

		// 1. Arrange
		routingRule := &proModels.RoutingRule{
			WorkspaceID: 1,
			RuleType:    "Asset",
			MatchValue:  "aws-cloud",
			Assignee:    "cloud-team@ranch.com",
			Role:        "Wrangler",
		}
		if err := store.CreateRoutingRule(ctx, routingRule); err != nil {
			t.Fatalf("Arrange Failed - Could not create routing rule: %v", err)
		}

		ticket := &models.Ticket{
			Source:             "Trivy",
			AssetIdentifier:    "aws-cloud",
			Severity:           "High",
			DedupeHash:         "hash-789",
			Title:              "Test Vuln",
			Status:             "Waiting to be Triaged", // 🚀 FIX: Valid DB Status
			TriageDueDate:      now.Add(24 * time.Hour),
			RemediationDueDate: now.Add(7 * 24 * time.Hour),
		}

		// 2. Act
		if err := store.CreateTicket(ctx, ticket); err != nil {
			t.Fatalf("Act Failed - Could not create ticket: %v", err)
		}

		// 3. Assert
		var dbStatus string
		if err := store.DB.QueryRow("SELECT status FROM tickets WHERE id = ?", ticket.ID).Scan(&dbStatus); err != nil {
			t.Fatalf("Assert Failed - Could not fetch status from DB: %v", err)
		}
		if dbStatus != "Assigned Out" {
			t.Errorf("Expected DB status to be 'Assigned Out', got '%s'", dbStatus)
		}

		var assignee string
		if err := store.DB.QueryRow("SELECT assignee FROM ticket_assignments WHERE ticket_id = ?", ticket.ID).Scan(&assignee); err != nil {
			t.Fatalf("Assert Failed - Could not fetch assignment from DB: %v", err)
		}
		if assignee != "cloud-team@ranch.com" {
			t.Errorf("Expected ticket to be assigned to cloud-team@ranch.com, got '%s'", assignee)
		}
	})
}
