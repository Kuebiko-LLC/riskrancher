package datastore

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSchemaMigrations(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	defer db.Close()

	migrations := []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);`,
		`ALTER TABLE users ADD COLUMN email TEXT;`,
	}

	err = RunMigrations(db, migrations)
	if err != nil {
		t.Fatalf("Initial migration failed: %v", err)
	}

	var version int
	db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if version != 2 {
		t.Errorf("Expected database to be at version 2, got %d", version)
	}

	err = RunMigrations(db, migrations)
	if err != nil {
		t.Fatalf("Idempotent migration failed: %v", err)
	}

	_, err = db.Exec("INSERT INTO users (name, email) VALUES ('Tim', 'tim@ranch.com')")
	if err != nil {
		t.Errorf("Migration 2 did not apply correctly! Column 'email' missing: %v", err)
	}
}
