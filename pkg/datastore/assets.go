package datastore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The asset inventory and the priority rubric. Both are configuration the
// Sheriff loads or edits; ingest reads them once per batch.

// UpsertAssets loads inventory rows, replacing any asset already known.
func (s *SQLiteStore) UpsertAssets(ctx context.Context, assets []domain.Asset) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO assets (asset_identifier, exposure, criticality, owner, notes)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(asset_identifier) DO UPDATE SET
			exposure = excluded.exposure, criticality = excluded.criticality,
			owner = excluded.owner, notes = excluded.notes, updated_at = CURRENT_TIMESTAMP`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range assets {
		if _, err := stmt.ExecContext(ctx, a.AssetIdentifier, a.Exposure, a.Criticality, a.Owner, a.Notes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAssets is the whole inventory, by name.
func (s *SQLiteStore) ListAssets(ctx context.Context) ([]domain.Asset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT asset_identifier, exposure, criticality, owner, notes, updated_at FROM assets ORDER BY asset_identifier`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		var a domain.Asset
		var updated sql.NullTime
		if err := rows.Scan(&a.AssetIdentifier, &a.Exposure, &a.Criticality, &a.Owner, &a.Notes, &updated); err != nil {
			return nil, err
		}
		a.UpdatedAt = updated.Time
		out = append(out, a)
	}
	return out, rows.Err()
}

// assetByID is one inventory row, or nil when the asset is not in it.
func (s *SQLiteStore) assetByID(ctx context.Context, id string) (*domain.Asset, error) {
	var a domain.Asset
	err := s.DB.QueryRowContext(ctx, `SELECT asset_identifier, exposure, criticality, owner, notes FROM assets WHERE asset_identifier = ?`, id).
		Scan(&a.AssetIdentifier, &a.Exposure, &a.Criticality, &a.Owner, &a.Notes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// assetsByIDs is the inventory rows for these assets, keyed by name; assets
// not in the inventory are simply absent.
func (s *SQLiteStore) assetsByIDs(ctx context.Context, q queryer, ids []string) (map[string]domain.Asset, error) {
	out := map[string]domain.Asset{}
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := q.QueryContext(ctx, `SELECT asset_identifier, exposure, criticality, owner, notes FROM assets WHERE asset_identifier IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var a domain.Asset
			if err := rows.Scan(&a.AssetIdentifier, &a.Exposure, &a.Criticality, &a.Owner, &a.Notes); err != nil {
				rows.Close()
				return nil, err
			}
			out[a.AssetIdentifier] = a
		}
		rows.Close()
	}
	return out, nil
}

// queryer is what assetsByIDs needs: a *sql.DB or a *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// GetRubric is the fourteen weights, in display order.
func (s *SQLiteStore) GetRubric(ctx context.Context) ([]domain.RubricWeight, error) {
	return readRubric(ctx, s.DB)
}

func readRubric(ctx context.Context, q queryer) ([]domain.RubricWeight, error) {
	rows, err := q.QueryContext(ctx, `SELECT kind, name, weight FROM rubric_weights`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]float64{}
	for rows.Next() {
		var w domain.RubricWeight
		if err := rows.Scan(&w.Kind, &w.Key, &w.Weight); err != nil {
			return nil, err
		}
		have[w.Kind+"/"+w.Key] = w.Weight
	}
	out := make([]domain.RubricWeight, 0, len(domain.RubricOrder))
	for _, w := range domain.RubricOrder {
		if v, ok := have[w.Kind+"/"+w.Key]; ok {
			out = append(out, domain.RubricWeight{Kind: w.Kind, Key: w.Key, Weight: v})
		}
	}
	return out, rows.Err()
}

// UpdateRubric sets the named weights; the set of names is fixed by the seed.
func (s *SQLiteStore) UpdateRubric(ctx context.Context, weights []domain.RubricWeight) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, w := range weights {
		if _, err := tx.ExecContext(ctx, `UPDATE rubric_weights SET weight = ? WHERE kind = ? AND name = ?`, w.Weight, w.Kind, w.Key); err != nil {
			return err
		}
	}
	return tx.Commit()
}
