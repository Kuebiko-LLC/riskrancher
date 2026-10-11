// File: RiskRancher/pro/storage/pro_db.go
package storage

import (
	"context"
	"database/sql"
	_ "embed" // 🚀 THE FIX: Import the embed package
	"log"

	models "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// 🚀 THE FIX: This tells the Go compiler to read the file and inject it into this variable at compile-time!
//
//go:embed pro_schema.sql
var proSchemaSQL string

// InjectProSchema applies the $4,999 Enterprise tables to the Core database
func InjectProSchema(db *sql.DB) {
	// 🚀 THE FIX: Run the ALTER TABLE auto-migrations BEFORE executing the schema!
	migrations := []string{
		"ALTER TABLE tickets ADD COLUMN is_cisa_kev BOOLEAN DEFAULT 0;",
		"ALTER TABLE tickets ADD COLUMN verification_requested_at DATETIME;",
		"ALTER TABLE tickets ADD COLUMN extension_count INTEGER DEFAULT 0;",
		"ALTER TABLE tickets ADD COLUMN risk_rationale TEXT;",
		"ALTER TABLE tickets ADD COLUMN risk_evidence TEXT;",
		"ALTER TABLE tickets ADD COLUMN risk_approved_by TEXT;",
		"ALTER TABLE tickets ADD COLUMN risk_approved_at DATETIME;",
		"ALTER TABLE tickets ADD COLUMN exception_expires_at DATETIME;",
		"ALTER TABLE tickets ADD COLUMN engagement_id INTEGER;",
		"ALTER TABLE pentest_reports ADD COLUMN body TEXT;",
		"ALTER TABLE pentest_reports ADD COLUMN engagement_id INTEGER;",
	}

	for _, query := range migrations {
		db.Exec(query) // Ignore errors; they just mean the column was already added!
	}

	// Now that the columns exist, it's safe to create the indexes and tables!
	if _, err := db.Exec(proSchemaSQL); err != nil {
		log.Fatalf("🚨 PRO FATAL: Could not inject Pro Schema: %v", err)
	}

	log.Println("🤠 RiskRancher: schema ready")
}

// ==========================================
// 💎 PRO ADMIN METHODS (Batch Ingestion Interceptor)
// ==========================================

func (s *ProSQLiteStore) ProcessIngestionBatch(ctx context.Context, source string, asset string, batch []models.Ticket) error {
	// 1. Run Pro Logic (Engine is now in the same package)
	engine := NewSuppressionEngine(s.db)
	err := engine.EvaluateBatch(ctx, batch)
	if err != nil {
		return err
	}

	// 2. Hand off cleanly to Core Logic's embedded store
	return s.SQLiteStore.ProcessIngestionBatch(ctx, source, asset, batch)
}
