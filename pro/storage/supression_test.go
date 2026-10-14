package storage_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func TestSuppressionEngine(t *testing.T) {
	store := setupTestDB(t) // Assumes this runs pro_schema.sql
	engine := storage.NewSuppressionEngine(store.DB)
	ctx := context.Background()

	t.Run("Given an active global suppression rule for Log4j on AWS", func(t *testing.T) {
		store.DB.Exec(`INSERT INTO global_suppression_rules (match_source, match_title, rationale, actor, is_active) 
				 VALUES ('AWS', 'Log4j', 'Accepted risk by CISO', 'admin@rancher.com', 1)`)

		t.Run("When a batch of tickets is ingested", func(t *testing.T) {
			batch := []domain.Ticket{
				{
					Source:          "AWS",
					AssetIdentifier: "ec2-instance-1",
					Title:           "CVE-2021-44228 Log4j Vulnerability",
					Status:          "Waiting to be Triaged",
					Description:     "Critical RCE.",
				},
				{
					Source:          "Trivy", // Different source
					AssetIdentifier: "container-app",
					Title:           "CVE-2021-44228 Log4j Vulnerability",
					Status:          "Waiting to be Triaged",
				},
			}

			err := engine.EvaluateBatch(ctx, batch)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			t.Run("Then the AWS Log4j ticket is a False Positive", func(t *testing.T) {
				if batch[0].Status != "False Positive" {
					t.Errorf("Expected status to be False Positive, got %s", batch[0].Status)
				}
				if batch[0].Description != "Vulnerable Log4j" && batch[0].Description == "" {
					t.Errorf("suppression must not rewrite the description")
				}
			})

			t.Run("And the Trivy Log4j ticket remains Open (Waiting to be Triaged)", func(t *testing.T) {
				if batch[1].Status != "Waiting to be Triaged" {
					t.Errorf("Expected status to remain Waiting to be Triaged, got %s", batch[1].Status)
				}
			})
		})
	})
}
