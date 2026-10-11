package datastore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	_ "modernc.org/sqlite" // We need the SQLite driver for the test
)

func setupTestDB(t *testing.T) *SQLiteStore {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite database: %v", err)
	}

	store := &SQLiteStore{DB: db}
	return store
}

func TestIngestionDiffEngine(t *testing.T) {
	store := setupTestDB(t)
	defer store.DB.Close()
	_, err := store.DB.Exec(`
        CREATE TABLE IF NOT EXISTS sla_policies (domain TEXT, severity TEXT, days_to_remediate INTEGER, max_extensions INTEGER, days_to_triage INTEGER);
        CREATE TABLE IF NOT EXISTS routing_rules (id INTEGER, rule_type TEXT, match_value TEXT, assignee TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS ticket_assignments (ticket_id INTEGER, assignee TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS ticket_activity (ticket_id INTEGER, actor TEXT, activity_type TEXT, new_value TEXT);
        
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            source TEXT, 
            asset_identifier TEXT, 
            title TEXT, 
            severity TEXT,
            description TEXT,
            status TEXT, 
            dedupe_hash TEXT UNIQUE,
            patched_at DATETIME,
            domain TEXT,
            triage_due_date DATETIME,
            remediation_due_date DATETIME
        )`)

	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	store.DB.Exec(`INSERT INTO tickets (source, asset_identifier, title, severity, description, status, dedupe_hash) VALUES 
		('Trivy', 'Server-A', 'Old Vuln', 'High', 'Desc', 'Waiting to be Triaged', 'hash_1_open')`)

	store.DB.Exec(`INSERT INTO tickets (source, asset_identifier, title, severity, description, status, dedupe_hash) VALUES 
		('Trivy', 'Server-A', 'Old Vuln', 'High', 'Desc', 'Waiting to be Triaged', 'hash_1_open')`)

	store.DB.Exec(`INSERT INTO tickets (source, asset_identifier, title, severity, description, status, dedupe_hash) VALUES 
		('Trivy', 'Server-A', 'Regressed Vuln', 'High', 'Desc', 'Patched', 'hash_2_patched')`)
	incomingPayload := []domain.Ticket{
		{Source: "Trivy", AssetIdentifier: "Server-A", Title: "Regressed Vuln", DedupeHash: "hash_2_patched"},
		{Source: "Trivy", AssetIdentifier: "Server-A", Title: "Brand New Vuln", DedupeHash: "hash_3_new"},
	}

	err = store.ProcessIngestionBatch(context.Background(), "Trivy", "Server-A", incomingPayload)
	if err != nil {
		t.Fatalf("Diff Engine failed: %v", err)
	}

	var status string

	store.DB.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = 'hash_1_open'`).Scan(&status)
	if status != "Patched" {
		t.Errorf("Expected hash_1_open to be Auto-Patched, got %s", status)
	}

	store.DB.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = 'hash_2_patched'`).Scan(&status)
	if status != "Waiting to be Triaged" {
		t.Errorf("Expected hash_2_patched to be Re-opened, got %s", status)
	}

	store.DB.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = 'hash_3_new'`).Scan(&status)
	if status != "Waiting to be Triaged" {
		t.Errorf("Expected hash_3_new to be newly created, got %s", status)
	}
}
