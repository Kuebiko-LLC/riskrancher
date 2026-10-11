package storage

import (
	"context"
	"strings"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// FindingsVisibleTo returns, from the requested ids, only the findings the
// caller is allowed to see: released findings (already in triage), findings in
// an engagement the caller owns, or anything when the caller is a Sheriff.
// This stops a report from pulling in another Bounty Hunter's held findings.
func (s *ProSQLiteStore) FindingsVisibleTo(ctx context.Context, ids []int, userEmail string, isSheriff bool) ([]coredomain.Ticket, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+2)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	sheriff := 0
	if isSheriff {
		sheriff = 1
	}
	args = append(args, sheriff, userEmail)

	q := `
		SELECT t.id, t.source, t.asset_identifier, t.title, t.description, t.recommended_remediation, t.severity, t.status
		FROM tickets t
		LEFT JOIN engagements e ON e.id = t.engagement_id
		WHERE t.id IN (` + strings.Join(placeholders, ",") + `)
		  AND (? = 1 OR t.released = 1 OR e.owner_email = ?)
		ORDER BY t.id`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []coredomain.Ticket
	for rows.Next() {
		var t coredomain.Ticket
		if err := rows.Scan(&t.ID, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.RecommendedRemediation, &t.Severity, &t.Status); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
