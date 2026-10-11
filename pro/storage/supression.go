package storage

import (
	"context"
	"database/sql"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type GlobalSuppressionRule struct {
	MatchSource sql.NullString
	MatchAsset  sql.NullString
	MatchTitle  sql.NullString
	Rationale   string
}

type SuppressionEngine struct {
	db *sql.DB
}

func NewSuppressionEngine(db *sql.DB) *SuppressionEngine {
	return &SuppressionEngine{db: db}
}

// EvaluateBatch applies suppression rules to a slice of tickets during ingestion.
// It mutates the tickets in-place before they hit the core database.
func (e *SuppressionEngine) EvaluateBatch(ctx context.Context, batch []domain.Ticket) error {
	// 1. Fetch active rules once per batch to avoid N+1 query performance hits
	query := `
		SELECT match_source, match_asset, match_title, rationale 
		FROM global_suppression_rules 
		WHERE is_active = 1
	`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []GlobalSuppressionRule
	for rows.Next() {
		var r GlobalSuppressionRule
		if err := rows.Scan(&r.MatchSource, &r.MatchAsset, &r.MatchTitle, &r.Rationale); err != nil {
			return err
		}
		rules = append(rules, r)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// 2. Fast exit if no rules are active
	if len(rules) == 0 {
		return nil
	}

	// 3. Evaluate each ticket in the batch against the rules
	for i := range batch {
		for _, rule := range rules {
			// If a condition is set in the DB, it MUST match.
			if rule.MatchSource.Valid && !strings.EqualFold(batch[i].Source, rule.MatchSource.String) {
				continue
			}
			if rule.MatchAsset.Valid && !strings.Contains(strings.ToLower(batch[i].AssetIdentifier), strings.ToLower(rule.MatchAsset.String)) {
				continue
			}
			// Use Title instead of CVE, since Title forms the DedupeHash in core
			if rule.MatchTitle.Valid && !strings.Contains(strings.ToLower(batch[i].Title), strings.ToLower(rule.MatchTitle.String)) {
				continue
			}

			// All defined conditions matched. Suppress the ticket.
			batch[i].Status = "Suppressed"
			batch[i].Description = "[AUTO-SUPPRESSED: " + rule.Rationale + "]\n\n" + batch[i].Description

			// Stop evaluating rules for this ticket once suppressed
			break
		}
	}
	return nil
}
