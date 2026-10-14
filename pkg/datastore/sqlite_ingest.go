package datastore

import (
	"context"
	"database/sql"
	"time"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (s *SQLiteStore) GetAdapters(ctx context.Context) ([]domain2.Adapter, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, name, source_name, findings_path, mapping_title, mapping_asset, mapping_severity, mapping_description, mapping_remediation FROM data_adapters")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var adapters []domain2.Adapter
	for rows.Next() {
		var a domain2.Adapter
		rows.Scan(&a.ID, &a.Name, &a.SourceName, &a.FindingsPath, &a.MappingTitle, &a.MappingAsset, &a.MappingSeverity, &a.MappingDescription, &a.MappingRemediation)
		adapters = append(adapters, a)
	}
	return adapters, nil
}

func (s *SQLiteStore) SaveAdapter(ctx context.Context, a domain2.Adapter) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO data_adapters (name, source_name, findings_path, mapping_title, mapping_asset, mapping_severity, mapping_description, mapping_remediation) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Name, a.SourceName, a.FindingsPath, a.MappingTitle, a.MappingAsset, a.MappingSeverity, a.MappingDescription, a.MappingRemediation)
	return err
}

func (s *SQLiteStore) GetAdapterByID(ctx context.Context, id int) (domain2.Adapter, error) {
	var a domain2.Adapter
	query := `
		SELECT 
			id, name, source_name, findings_path, 
			mapping_title, mapping_asset, mapping_severity, 
			IFNULL(mapping_description, ''), IFNULL(mapping_remediation, ''),
			created_at, updated_at
		FROM data_adapters 
		WHERE id = ?`

	err := s.DB.QueryRowContext(ctx, query, id).Scan(
		&a.ID, &a.Name, &a.SourceName, &a.FindingsPath,
		&a.MappingTitle, &a.MappingAsset, &a.MappingSeverity,
		&a.MappingDescription, &a.MappingRemediation,
		&a.CreatedAt, &a.UpdatedAt,
	)
	return a, err
}

func (s *SQLiteStore) DeleteAdapter(ctx context.Context, id int) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM data_adapters WHERE id = ?", id)
	return err
}

func (s *SQLiteStore) GetAdapterByName(ctx context.Context, name string) (domain2.Adapter, error) {
	var a domain2.Adapter
	query := `
		SELECT 
			id, name, source_name, findings_path, 
			mapping_title, mapping_asset, mapping_severity, 
			IFNULL(mapping_description, ''), IFNULL(mapping_remediation, '')
		FROM data_adapters 
		WHERE name = ?`

	err := s.DB.QueryRowContext(ctx, query, name).Scan(
		&a.ID, &a.Name, &a.SourceName, &a.FindingsPath,
		&a.MappingTitle, &a.MappingAsset, &a.MappingSeverity,
		&a.MappingDescription, &a.MappingRemediation,
	)
	return a, err
}

// ingestBatch is the diff engine: insert, reopen, update, autoclose for one source and asset.
// ProcessIngestionBatch (ingest_rules.go) runs the rules engine first and routes after.
func (s *SQLiteStore) ingestBatch(ctx context.Context, source, asset string, incoming []domain2.Ticket) error {
	slaMap, _ := s.buildSLAMap(ctx)

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for i := range incoming {
		if incoming[i].Domain == "" {
			incoming[i].Domain = "Vulnerability"
		}
		if incoming[i].Status == "" {
			incoming[i].Status = "Waiting to be Triaged"
		}
	}

	inserts, reopens, updates, closes, err := s.calculateDiffState(ctx, tx, source, asset, incoming)
	if err != nil {
		return err
	}

	if err := s.executeBatchMutations(ctx, tx, source, asset, slaMap, inserts, reopens, updates, closes); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteStore) calculateDiffState(ctx context.Context, tx *sql.Tx, source, asset string, incoming []domain2.Ticket) (inserts, reopens, descUpdates []domain2.Ticket, autocloses []string, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT dedupe_hash, status, COALESCE(description, ''), COALESCE(recommended_remediation, '') FROM tickets WHERE source = ? AND asset_identifier = ?`, source, asset)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer rows.Close()

	type existingRecord struct{ status, description, remediation string }
	existingMap := make(map[string]existingRecord)
	for rows.Next() {
		var hash, status, desc, fix string
		if err := rows.Scan(&hash, &status, &desc, &fix); err == nil {
			existingMap[hash] = existingRecord{status: status, description: desc, remediation: fix}
		}
	}

	incomingMap := make(map[string]bool)
	for _, ticket := range incoming {
		incomingMap[ticket.DedupeHash] = true
		existing, exists := existingMap[ticket.DedupeHash]
		if !exists {
			inserts = append(inserts, ticket)
		} else {
			if existing.status == "Patched" {
				reopens = append(reopens, ticket)
			}
			textChanged := (ticket.Description != "" && ticket.Description != existing.description) ||
				(ticket.RecommendedRemediation != "" && ticket.RecommendedRemediation != existing.remediation)
			if textChanged && existing.status != "Patched" && existing.status != "Risk Accepted" && existing.status != "False Positive" {
				descUpdates = append(descUpdates, ticket)
			}
		}
	}

	for hash, record := range existingMap {
		if !incomingMap[hash] && record.status != "Patched" && record.status != "Risk Accepted" && record.status != "False Positive" {
			autocloses = append(autocloses, hash)
		}
	}
	return inserts, reopens, descUpdates, autocloses, nil
}

func (s *SQLiteStore) executeBatchMutations(ctx context.Context, tx *sql.Tx, source, asset string, slaMap map[string]map[string]domain2.SLAPolicy, inserts, reopens, descUpdates []domain2.Ticket, autocloses []string) error {
	now := time.Now()

	// A. Inserts
	if len(inserts) > 0 {
		insertStmt, err := tx.PrepareContext(ctx, `INSERT INTO tickets (source, asset_identifier, title, severity, description, recommended_remediation, status, dedupe_hash, domain, is_cisa_kev, triage_due_date, remediation_due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer insertStmt.Close()

		for _, t := range inserts {
			daysToTriage, daysToRemediate := 3, 30
			if dMap, ok := slaMap[t.Domain]; ok {
				if policy, ok := dMap[t.Severity]; ok {
					daysToTriage, daysToRemediate = policy.DaysToTriage, policy.DaysToRemediate
				}
			}
			_, err := insertStmt.ExecContext(ctx, source, asset, t.Title, t.Severity, t.Description, t.RecommendedRemediation, t.Status, t.DedupeHash, t.Domain, t.IsCISAKEV, now.AddDate(0, 0, daysToTriage), now.AddDate(0, 0, daysToRemediate))
			if err != nil {
				return err
			}
		}
	}

	if len(reopens) > 0 {
		updateStmt, _ := tx.PrepareContext(ctx, `UPDATE tickets SET status = 'Waiting to be Triaged', patched_at = NULL, triage_due_date = ?, remediation_due_date = ?, updated_at = CURRENT_TIMESTAMP WHERE dedupe_hash = ?`)
		defer updateStmt.Close()
		for _, t := range reopens {
			// A finding that came back starts a fresh clock from the matrix
			daysToTriage, daysToRemediate := 3, 30
			if dMap, ok := slaMap[t.Domain]; ok {
				if policy, ok := dMap[t.Severity]; ok {
					daysToTriage, daysToRemediate = policy.DaysToTriage, policy.DaysToRemediate
				}
			}
			updateStmt.ExecContext(ctx, now.AddDate(0, 0, daysToTriage), now.AddDate(0, 0, daysToRemediate), t.DedupeHash)
			tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) SELECT id, 'Scan', 'scan_reopened', 'Patched', 'Waiting to be Triaged' FROM tickets WHERE dedupe_hash = ?`, t.DedupeHash)
		}
	}

	if len(descUpdates) > 0 {
		descStmt, _ := tx.PrepareContext(ctx, `UPDATE tickets SET description = CASE WHEN ? != '' THEN ? ELSE description END, recommended_remediation = CASE WHEN ? != '' THEN ? ELSE recommended_remediation END, updated_at = CURRENT_TIMESTAMP WHERE dedupe_hash = ?`)
		defer descStmt.Close()
		for _, t := range descUpdates {
			descStmt.ExecContext(ctx, t.Description, t.Description, t.RecommendedRemediation, t.RecommendedRemediation, t.DedupeHash)
		}
	}

	if len(autocloses) > 0 {
		closeStmt, _ := tx.PrepareContext(ctx, `UPDATE tickets SET status = 'Patched', patched_at = CURRENT_TIMESTAMP WHERE dedupe_hash = ?`)
		defer closeStmt.Close()
		for _, hash := range autocloses {
			tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) SELECT id, 'Scan', 'scan_closed', status, 'Patched' FROM tickets WHERE dedupe_hash = ?`, hash)
			closeStmt.ExecContext(ctx, hash)
		}
	}

	return nil
}

func (s *SQLiteStore) LogSync(ctx context.Context, source, status string, records int, errMsg string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sync_logs (source, status, records_processed, error_message) VALUES (?, ?, ?, ?)`, source, status, records, errMsg)
	return err
}

func (s *SQLiteStore) GetRecentSyncLogs(ctx context.Context, limit int) ([]domain2.SyncLog, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, source, status, records_processed, IFNULL(error_message, ''), created_at FROM sync_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []domain2.SyncLog
	for rows.Next() {
		var l domain2.SyncLog
		rows.Scan(&l.ID, &l.Source, &l.Status, &l.RecordsProcessed, &l.ErrorMessage, &l.CreatedAt)
		logs = append(logs, l)
	}
	return logs, nil
}
