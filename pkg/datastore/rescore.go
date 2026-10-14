package datastore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// A rescore re-decides open findings the way ingest would decide them today:
// the scanner's word through the current inventory, rubric, severity rules
// and KEV flag. It runs when an inventory is loaded, when the rubric is
// saved, when an asset is forgotten, and when a KEV catalog is loaded.

const openStatuses = `('Patched', 'Risk Accepted', 'False Positive')`

// rescoreOpen re-decides the open findings with these ids inside tx. A
// finding whose severity changed gets its two clocks again from created_at
// and the matrix, and one history line under actor. A finding whose score
// changed but not its severity gets the score and the line, not the clocks.
// Returns how many severities changed.
func (s *SQLiteStore) rescoreOpen(ctx context.Context, tx *sql.Tx, ids []int, actor string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	rubric := loadRubric(ctx, tx)
	triage, err := loadTriageRules(ctx, tx)
	if err != nil {
		return 0, err
	}
	slaMap, err := readSLAMap(ctx, tx)
	if err != nil {
		return 0, err
	}

	type row struct {
		id                 int
		source, asset, dom string
		scanner, severity  string
		score              sql.NullFloat64
		kev                bool
		created            sql.NullTime
	}
	var rows []row
	assetSet := map[string]bool{}
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		args := make([]any, 0, end-start)
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		rs, err := tx.QueryContext(ctx, `SELECT id, source, asset_identifier, domain, COALESCE(NULLIF(scanner_severity, ''), severity), severity, rubric_score, COALESCE(is_cisa_kev, 0), created_at
			FROM tickets WHERE id IN (?`+strings.Repeat(",?", len(args)-1)+`) AND status NOT IN `+openStatuses, args...)
		if err != nil {
			return 0, err
		}
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.id, &r.source, &r.asset, &r.dom, &r.scanner, &r.severity, &r.score, &r.kev, &r.created); err != nil {
				rs.Close()
				return 0, err
			}
			rows = append(rows, r)
			assetSet[r.asset] = true
		}
		rs.Close()
	}
	assetIDs := make([]string, 0, len(assetSet))
	for a := range assetSet {
		assetIDs = append(assetIDs, a)
	}
	assets, err := s.assetsByIDs(ctx, tx, assetIDs)
	if err != nil {
		return 0, err
	}

	changed := 0
	for _, r := range rows {
		var asset *domain.Asset
		if a, ok := assets[r.asset]; ok {
			asset = &a
		}
		severity, score := decideSeverity(rubric, asset, triage, r.source, r.asset, r.scanner, r.kev)
		scoreSame := (score == nil && !r.score.Valid) || (score != nil && r.score.Valid && *score == r.score.Float64)
		if severity == r.severity && scoreSame {
			continue
		}
		if severity != r.severity {
			created := r.created.Time
			if !r.created.Valid {
				created = time.Now()
			}
			triageDays, fixDays := slaDays(slaMap, r.dom, severity)
			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET severity = ?, rubric_score = ?, triage_due_date = ?, remediation_due_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
				severity, score, created.AddDate(0, 0, triageDays), created.AddDate(0, 0, fixDays), r.id); err != nil {
				return 0, err
			}
			changed++
		} else if _, err := tx.ExecContext(ctx, `UPDATE tickets SET rubric_score = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, score, r.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) VALUES (?, ?, 'rescored', ?, ?)`, r.id, actor, r.severity, severity); err != nil {
			return 0, err
		}
	}
	return changed, nil
}

// openTicketIDs lists open findings on these assets inside tx.
func openTicketIDs(ctx context.Context, tx *sql.Tx, assetIDs []string) ([]int, error) {
	var ids []int
	for start := 0; start < len(assetIDs); start += 500 {
		end := start + 500
		if end > len(assetIDs) {
			end = len(assetIDs)
		}
		args := make([]any, 0, end-start)
		for _, a := range assetIDs[start:end] {
			args = append(args, a)
		}
		rs, err := tx.QueryContext(ctx, `SELECT id FROM tickets WHERE asset_identifier IN (?`+strings.Repeat(",?", len(args)-1)+`) AND status NOT IN `+openStatuses, args...)
		if err != nil {
			return nil, err
		}
		for rs.Next() {
			var id int
			if err := rs.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rs.Close()
	}
	return ids, nil
}

// RescoreAssets re-decides the open findings on these assets, or on every
// asset in the inventory when assetIDs is nil. Returns how many severities
// changed.
func (s *SQLiteStore) RescoreAssets(ctx context.Context, assetIDs []string) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var ids []int
	if assetIDs == nil {
		rs, err := tx.QueryContext(ctx, `SELECT t.id FROM tickets t JOIN assets a ON a.asset_identifier = t.asset_identifier WHERE t.status NOT IN `+openStatuses)
		if err != nil {
			return 0, err
		}
		for rs.Next() {
			var id int
			if err := rs.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rs.Close()
	} else if ids, err = openTicketIDs(ctx, tx, assetIDs); err != nil {
		return 0, err
	}
	n, err := s.rescoreOpen(ctx, tx, ids, "Rubric")
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// DeleteAsset forgets an asset; its open findings go back to the scanner's
// word. Returns how many severities changed.
func (s *SQLiteStore) DeleteAsset(ctx context.Context, assetIdentifier string) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE asset_identifier = ?`, assetIdentifier)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNoSuchAsset
	}
	ids, err := openTicketIDs(ctx, tx, []string{assetIdentifier})
	if err != nil {
		return 0, err
	}
	n, err := s.rescoreOpen(ctx, tx, ids, "Rubric")
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// ErrNoSuchAsset is returned when the asset to forget is not in the inventory.
var ErrNoSuchAsset = errors.New("asset not in the inventory")
