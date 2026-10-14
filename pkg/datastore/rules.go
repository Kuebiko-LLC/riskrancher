package datastore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// --- Ticket workflow ---
func (s *SQLiteStore) BulkUpdateStatusAndAssign(ctx context.Context, ticketIDs []int, status, assignee, comment, actor string) (string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	for _, id := range ticketIDs {
		if status != "" {
			var oldStatus string
			tx.QueryRowContext(ctx, "SELECT status FROM tickets WHERE id = ?", id).Scan(&oldStatus)

			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, id); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) VALUES (?, ?, 'status_change', ?, ?)`, id, actor, oldStatus, status); err != nil {
				return "", err
			}
		}
		if assignee != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET assignee = ?, assigned_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, assignee, id); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM ticket_assignments WHERE ticket_id = ? AND role = 'Wrangler'`, id); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_assignments (ticket_id, assignee, role) VALUES (?, ?, 'Wrangler')`, id, assignee); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'assigned_to', ?)`, id, actor, assignee); err != nil {
				return "", err
			}
		}
		if comment != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, ?, 'comment', ?)`, id, actor, comment); err != nil {
				return "", err
			}
		}
	}

	var batchToken string
	if assignee != "" || status == "Pending Risk Approval" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		batchToken = hex.EncodeToString(b)
		idsJSON, _ := json.Marshal(ticketIDs)

		_, err = tx.ExecContext(ctx, `
          INSERT INTO magic_batches (token, created_by, expires_at, ticket_ids) 
          VALUES (?, ?, DATETIME('now', '+90 days'), ?)`,
			batchToken, actor, string(idsJSON))
		if err != nil {
			return "", err
		}
	}

	return batchToken, tx.Commit()
}

// --- Auto-triage rules ---
func (s *SQLiteStore) CreateAutoTriageRule(ctx context.Context, rule *domain.AutoTriageRule) error {
	res, err := s.DB.ExecContext(ctx,
		"INSERT INTO auto_triage_rules (match_source, match_asset, match_cve, action_type, action_value) VALUES (?, ?, ?, ?, ?)",
		rule.MatchSource, rule.MatchAsset, rule.MatchCVE, rule.ActionType, rule.ActionValue)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	rule.ID = int(id)
	return nil
}

// Audit log feed
func (s *SQLiteStore) GetGlobalActivityFeed(ctx context.Context, limit int) ([]domain.FeedItem, error) {
	query := `
		SELECT actor, action || ' ' || target_resource, status_code, 
		CASE WHEN status_code >= 400 THEN error_details ELSE 'Success' END, 
		created_at 
		FROM audit_logs 
		ORDER BY created_at DESC 
		LIMIT ?`

	rows, err := s.DB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feed []domain.FeedItem
	for rows.Next() {
		var item domain.FeedItem
		var createdAt string
		var statusCode int
		rows.Scan(&item.Actor, &item.ActivityType, &statusCode, &item.NewValue, &createdAt)

		// Optional: Clean up the time formatting
		item.TimeAgo = createdAt
		feed = append(feed, item)
	}
	return feed, nil
}

func (s *SQLiteStore) GetAutoTriageRules(ctx context.Context) ([]domain.AutoTriageRule, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, match_source, match_asset, match_cve, action_type, action_value, created_at FROM auto_triage_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []domain.AutoTriageRule
	for rows.Next() {
		var r domain.AutoTriageRule
		if err := rows.Scan(&r.ID, &r.MatchSource, &r.MatchAsset, &r.MatchCVE, &r.ActionType, &r.ActionValue, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *SQLiteStore) DeleteAutoTriageRule(ctx context.Context, ruleID int) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM auto_triage_rules WHERE id = ?", ruleID)
	return err
}

// domain.DashboardTicket is a ticket with its portal token

// GetDashboardTickets is the dashboard query plus the portal token per ticket
func (s *SQLiteStore) GetDashboardTicketsWithPortals(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]domain.DashboardTicket, int, map[string]int, error) {

	// 1. The base dashboard query
	coreTickets, total, metrics, err := s.GetDashboardTickets(ctx, tabStatus, filter, assetFilter, userEmail, userRole, limit, offset)
	if err != nil {
		return nil, 0, nil, err
	}

	var proTickets []domain.DashboardTicket

	// 2. If no tickets were returned, skip enrichment
	if len(coreTickets) == 0 {
		return proTickets, total, metrics, nil
	}

	// 3. Fetch the portal tokens for the returned tickets
	for _, t := range coreTickets {
		pt := domain.DashboardTicket{Ticket: t, RequestKind: requestKind(t.RiskRationale)}
		var token string
		err := s.DB.QueryRowContext(ctx, `
          SELECT m.token 
          FROM magic_batches m, json_each(m.ticket_ids) j 
          WHERE j.value = ? AND m.is_revoked = 0 AND m.expires_at > CURRENT_TIMESTAMP 
          ORDER BY m.created_at DESC LIMIT 1`, t.ID).Scan(&token)

		if err == nil {
			pt.MagicToken = token
		}
		proTickets = append(proTickets, pt)
	}

	return proTickets, total, metrics, nil
}

// requestKind reads what the owner asked for from the stored rationale,
// which the portal writes as "<kind>: <reason>".
func requestKind(rationale string) string {
	for _, kind := range []string{"Time Extension", "Risk Acceptance"} {
		if strings.HasPrefix(rationale, kind+":") {
			return kind
		}
	}
	return ""
}

// Immutable audit logging
func (s *SQLiteStore) LogAuditAction(ctx context.Context, actor, action, resource string, statusCode int, errorDetails, ip string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs (actor, action, target_resource, status_code, error_details, ip_address) 
        VALUES (?, ?, ?, ?, ?, ?)`,
		actor, action, resource, statusCode, errorDetails, ip)
	return err
}

// The ingestion rules engine: suppression, triage, routing

// ==========================================
// Rules engine CRUD
// ==========================================

// CreateSuppressionRule logs a false positive: the finding closes now if it is
// open, and the rules engine keeps it closed on every scan after.
func (s *SQLiteStore) CreateSuppressionRule(ctx context.Context, rule *domain.SuppressionRule) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		"INSERT INTO suppression_rules (dedupe_hash, asset_identifier, rationale, actor) VALUES (?, ?, ?, ?)",
		rule.DedupeHash, rule.AssetIdentifier, rule.Rationale, rule.Actor)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE tickets SET status = 'False Positive', latest_comment = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE dedupe_hash = ? AND asset_identifier = ? AND status NOT IN ('Patched', 'Risk Accepted', 'False Positive')`,
		"False positive: "+rule.Rationale, rule.DedupeHash, rule.AssetIdentifier); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	rule.ID = int(id)
	return nil
}

// ListSuppressionRules returns the logged false positives, newest first.
func (s *SQLiteStore) ListSuppressionRules(ctx context.Context) ([]domain.SuppressionRule, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, dedupe_hash, asset_identifier, rationale, actor, created_at FROM suppression_rules ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []domain.SuppressionRule{}
	for rows.Next() {
		var r domain.SuppressionRule
		if err := rows.Scan(&r.ID, &r.DedupeHash, &r.AssetIdentifier, &r.Rationale, &r.Actor, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteSuppressionRule un-logs a false positive; the next scan treats the finding as new.
func (s *SQLiteStore) DeleteSuppressionRule(ctx context.Context, id int) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM suppression_rules WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) CreateRoutingRule(ctx context.Context, rule *domain.RoutingRule) error {
	res, err := s.DB.ExecContext(ctx,
		"INSERT INTO routing_rules (rule_type, match_value, assignee, role) VALUES (?, ?, ?, ?)",
		rule.RuleType, rule.MatchValue, rule.Assignee, rule.Role)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	rule.ID = int(id)
	return nil
}

// ==========================================
// CISA KEV catalog
// ==========================================

// cveToken finds CVE ids in free text, in any letter case.
var cveToken = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// SyncCISACatalog replaces the stored KEV catalog and re-flags findings.
// It reads every finding that mentions a CVE once and matches the ids in Go,
// so the cost is one pass over the table, not one scan per catalog entry.
func (s *SQLiteStore) SyncCISACatalog(ctx context.Context, feed *domain.CISAFeed) error {
	known := make(map[string]bool, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		known[strings.ToUpper(v.CVEID)] = true
	}

	// One pass: which findings name a catalog CVE
	rows, err := s.DB.QueryContext(ctx, `SELECT id, title, description FROM tickets WHERE title LIKE '%CVE-%' OR description LIKE '%CVE-%'`)
	if err != nil {
		return err
	}
	var hits []int
	for rows.Next() {
		var id int
		var title string
		var desc sql.NullString
		if err := rows.Scan(&id, &title, &desc); err != nil {
			rows.Close()
			return err
		}
		for _, m := range cveToken.FindAllString(title+" "+desc.String, -1) {
			if known[strings.ToUpper(m)] {
				hits = append(hits, id)
				break
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM cisa_catalog"); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cisa_catalog (cve_id, date_added) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, v := range feed.Vulnerabilities {
		if _, err := stmt.ExecContext(ctx, v.CVEID, v.DateAdded); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, "UPDATE tickets SET is_cisa_kev = 0 WHERE is_cisa_kev = 1"); err != nil {
		return err
	}
	const chunk = 500
	for i := 0; i < len(hits); i += chunk {
		end := i + chunk
		if end > len(hits) {
			end = len(hits)
		}
		args := make([]any, 0, end-i)
		marks := make([]string, 0, end-i)
		for _, id := range hits[i:end] {
			args = append(args, id)
			marks = append(marks, "?")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tickets SET is_cisa_kev = 1 WHERE id IN ("+strings.Join(marks, ",")+")", args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetRoutingRules(ctx context.Context) ([]domain.RoutingRule, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, rule_type, match_value, assignee, role, created_at FROM routing_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []domain.RoutingRule
	for rows.Next() {
		var r domain.RoutingRule
		if err := rows.Scan(&r.ID, &r.RuleType, &r.MatchValue, &r.Assignee, &r.Role, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *SQLiteStore) DeleteRoutingRule(ctx context.Context, id int) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM routing_rules WHERE id = ?", id)
	return err
}
