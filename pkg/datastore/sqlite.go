package datastore

import (
	"context"
	"database/sql"
	"strings"
	"sync"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type SQLiteStore struct {
	DB *sql.DB

	// The loaded KEV catalog, read once and kept until the next sync, so
	// ingest can flag a finding as it lands without a query per row.
	kevMu     sync.RWMutex
	kevCVEs   map[string]bool
	kevLoaded bool
}

// kevSet returns the catalog CVE ids, loading them on first use.
func (s *SQLiteStore) kevSet(ctx context.Context) map[string]bool {
	s.kevMu.RLock()
	if s.kevLoaded {
		defer s.kevMu.RUnlock()
		return s.kevCVEs
	}
	s.kevMu.RUnlock()

	s.kevMu.Lock()
	defer s.kevMu.Unlock()
	if s.kevLoaded {
		return s.kevCVEs
	}
	set := map[string]bool{}
	rows, err := s.DB.QueryContext(ctx, `SELECT cve_id FROM cisa_catalog`)
	if err == nil {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				set[strings.ToUpper(id)] = true
			}
		}
		rows.Close()
	}
	s.kevCVEs, s.kevLoaded = set, true
	return set
}

// forgetKEV drops the cached catalog so the next ingest reads the new one.
func (s *SQLiteStore) forgetKEV() {
	s.kevMu.Lock()
	s.kevLoaded, s.kevCVEs = false, nil
	s.kevMu.Unlock()
}

var _ domain.TicketStore = (*SQLiteStore)(nil)

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{DB: db}
}
