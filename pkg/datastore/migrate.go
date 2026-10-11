package datastore

import (
	"database/sql"
	"fmt"
	"log"
)

// RunMigrations ensures the database schema matches the binary version
func RunMigrations(db *sql.DB, migrations []string) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %v", err)
	}

	var currentVersion int
	err = db.QueryRow("SELECT IFNULL(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to read current schema version: %v", err)
	}

	for i, query := range migrations {
		migrationVersion := i + 1

		if migrationVersion > currentVersion {
			log.Printf("🚀 Applying database migration v%d...", migrationVersion)

			// Start a transaction so if the ALTER TABLE fails, it rolls back cleanly
			tx, err := db.Begin()
			if err != nil {
				return err
			}

			if _, err := tx.Exec(query); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration v%d failed: %v", migrationVersion, err)
			}

			if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", migrationVersion); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to record migration v%d: %v", migrationVersion, err)
			}

			if err := tx.Commit(); err != nil {
				return err
			}

			log.Printf("✅ Migration v%d applied successfully.", migrationVersion)
		}
	}

	return nil
}
