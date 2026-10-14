package datastore

import (
	"database/sql"
	"embed"
	_ "embed"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

//go:embed defaults/*.json
var defaultAdaptersFS embed.FS

func InitDB(dbPath string) *sql.DB {

	dir := filepath.Dir(dbPath)

	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	migrations := []string{
		schemaSQL,
		// v2: drop the hardcoded role CHECK on users (roles are validated in the
		// app layer now, which supports Bounty Hunter and future custom roles).
		// SQLite can't alter a CHECK in place, so rebuild the table.
		`CREATE TABLE users_rebuild (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			full_name TEXT NOT NULL,
			global_role TEXT NOT NULL,
			department TEXT NOT NULL DEFAULT 'Security',
			is_active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(department) REFERENCES departments(name) ON DELETE SET DEFAULT
		);
		INSERT INTO users_rebuild (id,email,password_hash,full_name,global_role,department,is_active,created_at)
			SELECT id,email,password_hash,full_name,global_role,department,is_active,created_at FROM users;
		DROP TABLE users;
		ALTER TABLE users_rebuild RENAME TO users;`,
		// v3: findings held in an unreleased engagement are hidden from the
		// triage queue until released. Normal findings default to visible (1).
		`ALTER TABLE tickets ADD COLUMN released INTEGER NOT NULL DEFAULT 1;`,
		// v4: structured pentest fields on findings (for report findings).
		`ALTER TABLE tickets ADD COLUMN cvss_vector TEXT;
		 ALTER TABLE tickets ADD COLUMN cvss_score REAL;
		 ALTER TABLE tickets ADD COLUMN cwe TEXT;
		 ALTER TABLE tickets ADD COLUMN business_impact TEXT;`,
		// v5: the Holding Pen pages by asset. This covering index lets the page
		// query walk assets in order and stop at LIMIT, so a page costs the same
		// at a million findings as at thirty.
		`CREATE INDEX IF NOT EXISTS idx_tickets_asset_status ON tickets(asset_identifier, status, released);`,
		// v6: the dashboard's headline counts (open criticals, overdue) read
		// these instead of filtering a severity or due-date range row by row.
		`CREATE INDEX IF NOT EXISTS idx_tickets_severity_status ON tickets(severity, status, released);
		 CREATE INDEX IF NOT EXISTS idx_tickets_remediation_due ON tickets(remediation_due_date, status, released);`,
	}

	if err := RunMigrations(db, migrations); err != nil {
		log.Fatalf("Database upgrade failed! Halting boot to protect data: %v", err)
	}

	SeedAdapters(db)

	return db
}

// SeedAdapters reads the embedded JSON files and UPSERTs them into SQLite
func SeedAdapters(db *sql.DB) {
	files, err := defaultAdaptersFS.ReadDir("defaults")
	if err != nil {
		log.Printf("No default adapters found or failed to read: %v", err)
		return
	}

	for _, file := range files {
		data, err := defaultAdaptersFS.ReadFile("defaults/" + file.Name())
		if err != nil {
			log.Printf("Failed to read adapter file %s: %v", file.Name(), err)
			continue
		}

		var adapter domain.Adapter
		if err := json.Unmarshal(data, &adapter); err != nil {
			log.Printf("Failed to parse adapter JSON %s: %v", file.Name(), err)
			continue
		}

		query := `
			INSERT INTO data_adapters (
				name, source_name, findings_path, mapping_title, 
				mapping_asset, mapping_severity, mapping_description, mapping_remediation
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				source_name = excluded.source_name,
				findings_path = excluded.findings_path,
				mapping_title = excluded.mapping_title,
				mapping_asset = excluded.mapping_asset,
				mapping_severity = excluded.mapping_severity,
				mapping_description = excluded.mapping_description,
				mapping_remediation = excluded.mapping_remediation,
				updated_at = CURRENT_TIMESTAMP;
		`

		_, err = db.Exec(query,
			adapter.Name, adapter.SourceName, adapter.FindingsPath, adapter.MappingTitle,
			adapter.MappingAsset, adapter.MappingSeverity, adapter.MappingDescription, adapter.MappingRemediation,
		)

		if err != nil {
			log.Printf("Failed to seed adapter %s to DB: %v", adapter.Name, err)
		} else {
			log.Printf("🔌 Successfully loaded adapter: %s", adapter.Name)
		}
	}
}
