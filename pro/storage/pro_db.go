// File: RiskRancher/pro/storage/pro_db.go
package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"log"

	models "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

//

// InjectProSchema is kept for its callers; the schema is applied by InitDB.
func InjectProSchema(db *sql.DB) {
	// The whole schema lives in pkg/datastore/schema.sql and is applied by
	// InitDB. Kept so existing callers keep compiling.
	log.Println("🤠 RiskRancher: schema ready")
}

// ==========================================
// Batch ingestion: rules first, then the base store
// ==========================================

func (s *ProSQLiteStore) ProcessIngestionBatch(ctx context.Context, source string, asset string, batch []models.Ticket) error {
	// 1. Run the suppression rules
	engine := NewSuppressionEngine(s.db)
	err := engine.EvaluateBatch(ctx, batch)
	if err != nil {
		return err
	}

	// 2. Hand off to the embedded base store
	return s.SQLiteStore.ProcessIngestionBatch(ctx, source, asset, batch)
}
