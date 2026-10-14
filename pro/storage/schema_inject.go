package storage

import (
	"database/sql"
	_ "embed"
	"log"
)

//

// InjectProSchema is kept for its callers; the schema is applied by InitDB.
func InjectProSchema(db *sql.DB) {
	// The whole schema lives in pkg/datastore/schema.sql and is applied by
	// InitDB. Kept so existing callers keep compiling.
	log.Println("🤠 RiskRancher: schema ready")
}
