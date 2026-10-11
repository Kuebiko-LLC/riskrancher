package sla_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// GetSLAPolicy simulates the core engine function that fetches SLA rules
func GetSLAPolicy(db *sql.DB, domain string, severity string) (daysToRemediate int, maxExtensions int, err error) {
	query := `SELECT days_to_remediate, max_extensions FROM sla_policies WHERE domain = ? AND severity = ?`
	err = db.QueryRow(query, domain, severity).Scan(&daysToRemediate, &maxExtensions)
	return daysToRemediate, maxExtensions, err
}

// setupTestDB spins up an isolated, in-memory database for testing
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	schema := `
		CREATE TABLE domains (name TEXT PRIMARY KEY);
		CREATE TABLE sla_policies (
			domain TEXT NOT NULL,
			severity TEXT NOT NULL,
			days_to_remediate INTEGER NOT NULL,
			max_extensions INTEGER NOT NULL DEFAULT 3,
			PRIMARY KEY (domain, severity)
		);
		INSERT INTO domains (name) VALUES ('Vulnerability'), ('Privacy'), ('Incident');
		INSERT INTO sla_policies (domain, severity, days_to_remediate, max_extensions) VALUES
			('Vulnerability', 'Critical', 14, 1),
			('Vulnerability', 'High', 30, 2),
			('Privacy', 'Critical', 3, 0),
			('Incident', 'Critical', 1, 0);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to execute test schema: %v", err)
	}
	return db
}

func TestSLAEngine(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tests := []struct {
		name             string
		domain           string
		severity         string
		expectDays       int
		expectExtensions int
		expectError      bool
	}{
		{
			name:             "VM Critical (Standard)",
			domain:           "Vulnerability",
			severity:         "Critical",
			expectDays:       14,
			expectExtensions: 1,
			expectError:      false,
		},
		{
			name:             "Privacy Critical (Strict 72-hour, No Extensions)",
			domain:           "Privacy",
			severity:         "Critical",
			expectDays:       3,
			expectExtensions: 0,
			expectError:      false,
		},
		{
			name:             "Incident Critical (24-hour, No Extensions)",
			domain:           "Incident",
			severity:         "Critical",
			expectDays:       1,
			expectExtensions: 0,
			expectError:      false,
		},
		{
			name:        "Unknown Domain (Should Fail)",
			domain:      "PhysicalSecurity",
			severity:    "Critical",
			expectError: true,
		},
		{
			name:        "Unknown Severity (Should Fail)",
			domain:      "Vulnerability",
			severity:    "SuperCritical",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			days, extensions, err := GetSLAPolicy(db, tt.domain, tt.severity)

			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v, got: %v", tt.expectError, err)
			}

			if tt.expectError {
				return
			}

			if days != tt.expectDays {
				t.Errorf("expected %d days, got %d", tt.expectDays, days)
			}
			if extensions != tt.expectExtensions {
				t.Errorf("expected %d max extensions, got %d", tt.expectExtensions, extensions)
			}
		})
	}
}
