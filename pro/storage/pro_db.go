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

// InjectProSchema applies the $4,999 Enterprise tables to the Core database
func InjectProSchema(db *sql.DB) {
	// The whole schema lives in pkg/datastore/schema.sql and is applied by
	// InitDB. Kept so existing callers keep compiling.
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
