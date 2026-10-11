// File: RiskRancher/pro/storage/pro_license.go
package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// SaveLicenseKey ensures the settings table exists and saves the encrypted JWT token
func (s *ProSQLiteStore) SaveLicenseKey(ctx context.Context, token string) error {
	// 1. Ensure our Enterprise settings table exists
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pro_settings (
			id INTEGER PRIMARY KEY CHECK (id = 1), -- Enforce a single row
			license_key TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to ensure pro_settings table: %w", err)
	}

	// 2. Upsert the key
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO pro_settings (id, license_key) 
		VALUES (1, ?) 
		ON CONFLICT(id) DO UPDATE SET license_key = excluded.license_key
	`, token)

	return err
}

// GetLicenseKey retrieves the saved token at boot time
func (s *ProSQLiteStore) GetLicenseKey(ctx context.Context) (string, error) {
	var key string
	err := s.db.QueryRowContext(ctx, `SELECT license_key FROM pro_settings WHERE id = 1`).Scan(&key)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No key saved yet, which is fine!
		}
		return "", err
	}
	return key, nil
}
