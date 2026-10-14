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

	// schema.sql is the baseline: the whole schema for a fresh install, applied
	// as version 1. Changes to a database that already exists in the field go
	// in as migrations appended below, one entry per version, and the ledger
	// (schema_migrations) records how far a database has been upgraded.
	//
	// While nothing runs in production, edit the baseline and reprovision
	// (delete data/riskrancher.db). Once an install exists that must keep its
	// data, leave the baseline alone and append a migration instead.
	migrations := []string{
		schemaSQL,
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
			log.Printf("Successfully loaded adapter: %s", adapter.Name)
		}
	}
}
