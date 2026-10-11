package datastore

import (
	"database/sql"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type SQLiteStore struct {
	DB *sql.DB
}

var _ domain.TicketStore = (*SQLiteStore)(nil)

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{DB: db}
}
