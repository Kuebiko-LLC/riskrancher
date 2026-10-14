package storage

import (
	"context"
	"fmt"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// GetCanonicalApps retrieves the core logical applications we want to group infrastructure under.
func (s *ProSQLiteStore) GetCanonicalApps(ctx context.Context) ([]domain.Application, error) {
	query := `SELECT id, name FROM applications`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applications: %w", err)
	}
	defer rows.Close()

	var apps []domain.Application
	for rows.Next() {
		var app domain.Application
		if err := rows.Scan(&app.ID, &app.Name); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

// GetUnverifiedAliases fetches raw, disjointed infrastructure strings that haven't been mapped yet.
func (s *ProSQLiteStore) GetUnverifiedAliases(ctx context.Context) ([]domain.AssetAlias, error) {
	query := `
		SELECT id, alias, layer, discovery_source 
		FROM asset_aliases 
		WHERE target_application_id IS NULL`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unverified aliases: %w", err)
	}
	defer rows.Close()

	var aliases []domain.AssetAlias
	for rows.Next() {
		var alias domain.AssetAlias
		if err := rows.Scan(&alias.ID, &alias.Alias, &alias.Layer, &alias.DiscoverySource); err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

// InsertMatchProposal upserts a high-confidence match from the AI engine for Analyst review.
func (s *ProSQLiteStore) InsertMatchProposal(ctx context.Context, proposal domain.MatchmakerProposal) error {
	query := `
		INSERT INTO matchmaker_proposals (source_alias_id, target_application_id, confidence_score, reasoning)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source_alias_id, target_application_id) 
		DO UPDATE SET 
			confidence_score = excluded.confidence_score,
			reasoning = excluded.reasoning,
			updated_at = CURRENT_TIMESTAMP`

	_, err := s.db.ExecContext(ctx, query,
		proposal.SourceAliasID,
		proposal.TargetApplicationID,
		proposal.ConfidenceScore,
		proposal.Reasoning,
	)
	return err
}
