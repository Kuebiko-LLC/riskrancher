package datastore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
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

			// Patched stamps the close; leaving Patched clears it, so MTTR sees hand verifies too
			if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = ?, patched_at = CASE WHEN ? = 'Patched' THEN CURRENT_TIMESTAMP ELSE NULL END, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, status, id); err != nil {
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
          INSERT INTO magic_batches (token, created_by, expires_at, kind, assignee, ticket_ids)
          VALUES (?, ?, DATETIME('now', '+90 days'), 'owner', ?, ?)`,
			batchToken, actor, assignee, string(idsJSON))
		if err != nil {
			return "", err
		}
	}
	if err := revokeStaleLinks(ctx, tx, ticketIDs); err != nil {
		return "", err
	}

	return batchToken, tx.Commit()
}

// revokeStaleLinks ends every link that no longer has work on it: an owner's
// link once none of its findings is still that owner's and open, an
// approver's link once none of its findings waits for a decision. Called
// inside the transaction that moved the findings.
func revokeStaleLinks(ctx context.Context, tx *sql.Tx, ticketIDs []int) error {
	if len(ticketIDs) == 0 {
		return nil
	}
	idsJSON, _ := json.Marshal(ticketIDs)
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT m.token, m.kind, m.assignee, m.ticket_ids FROM magic_batches m, json_each(m.ticket_ids) j
		WHERE m.is_revoked = 0 AND j.value IN (SELECT value FROM json_each(?))`, string(idsJSON))
	if err != nil {
		return err
	}
	type batch struct{ token, kind, assignee, ids string }
	var batches []batch
	for rows.Next() {
		var b batch
		if err := rows.Scan(&b.token, &b.kind, &b.assignee, &b.ids); err == nil {
			batches = append(batches, b)
		}
	}
	rows.Close()
	for _, b := range batches {
		var live int
		if b.kind == "approver" {
			tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tickets WHERE id IN (SELECT value FROM json_each(?)) AND status = 'Pending Risk Approval'`, b.ids).Scan(&live)
		} else {
			tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tickets WHERE id IN (SELECT value FROM json_each(?)) AND assignee = ? AND status IN ('Assigned Out', 'Pending Verification', 'Pending Risk Approval')`, b.ids, b.assignee).Scan(&live)
		}
		if live == 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE magic_batches SET is_revoked = 1 WHERE token = ?`, b.token); err != nil {
				return err
			}
		}
	}
	return nil
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

	var withPortals []domain.DashboardTicket

	// 2. If no tickets were returned, skip enrichment
	if len(coreTickets) == 0 {
		return withPortals, total, metrics, nil
	}

	// 3. The inventory rows for the page's assets, one query
	seen := map[string]bool{}
	var assetIDs []string
	for _, t := range coreTickets {
		if !seen[t.AssetIdentifier] {
			seen[t.AssetIdentifier] = true
			assetIDs = append(assetIDs, t.AssetIdentifier)
		}
	}
	assets, err := s.assetsByIDs(ctx, s.DB, assetIDs)
	if err != nil {
		return nil, 0, nil, err
	}
	triage, _ := loadTriageRules(ctx, s.DB)

	// 4. Fetch the portal tokens for the returned tickets
	for _, t := range coreTickets {
		pt := domain.DashboardTicket{Ticket: t, RequestKind: requestKind(t.RiskRationale)}
		var asset *domain.Asset
		if a, ok := assets[t.AssetIdentifier]; ok {
			asset = &a
			pt.AssetExposure, pt.AssetCriticality = a.Exposure, a.Criticality
		}
		pt.ContextLine = contextLine(t, asset, triage)
		var token string
		err := s.DB.QueryRowContext(ctx, `
          SELECT m.token 
          FROM magic_batches m, json_each(m.ticket_ids) j 
          WHERE j.value = ? AND m.is_revoked = 0 AND m.expires_at > CURRENT_TIMESTAMP 
          ORDER BY m.created_at DESC LIMIT 1`, t.ID).Scan(&token)

		if err == nil {
			pt.MagicToken = token
		}
		withPortals = append(withPortals, pt)
	}

	return withPortals, total, metrics, nil
}

// contextLine is the one-line account of how a finding's priority was reached:
// the scanner's word, the asset's two multipliers and the score when the asset
// is in the inventory, and the rule or the KEV flag when one of those decided.
func contextLine(t domain.Ticket, asset *domain.Asset, triage []triageRule) string {
	scanner := t.ScannerSeverity
	if scanner == "" {
		scanner = t.Severity
	}
	line := "Scanner said " + scanner + "."
	if asset != nil && t.RubricScore != nil {
		line += " " + asset.Exposure + " x " + asset.Criticality + ", score " + strconv.FormatFloat(*t.RubricScore, 'f', -1, 64) + "."
	} else {
		line += " Asset not in the inventory."
	}
	if t.IsCISAKEV {
		return line + " Known exploited: Critical."
	}
	for _, rule := range triage {
		if rule.action != "DowngradeSeverity" || (rule.source != "" && rule.source != t.Source) || (rule.asset != "" && rule.asset != t.AssetIdentifier) {
			continue
		}
		line += " Severity rule: " + domain.NormalizeSeverity(rule.value) + "."
		break
	}
	return line
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

// DeleteSuppressionRule withdraws a logged false positive: the finding it
// closed goes back on the queue, and the next scan keeps it open.
func (s *SQLiteStore) DeleteSuppressionRule(ctx context.Context, id int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hash, asset string
	if err := tx.QueryRowContext(ctx, `SELECT dedupe_hash, asset_identifier FROM suppression_rules WHERE id = ?`, id).Scan(&hash, &asset); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM suppression_rules WHERE id = ?`, id); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tickets WHERE dedupe_hash = ? AND asset_identifier = ? AND status = 'False Positive'`, hash, asset)
	if err != nil {
		return err
	}
	var reopened []int
	for rows.Next() {
		var tid int
		if err := rows.Scan(&tid); err == nil {
			reopened = append(reopened, tid)
		}
	}
	rows.Close()
	for _, tid := range reopened {
		var domainName, severity string
		if err := tx.QueryRowContext(ctx, `SELECT domain, severity FROM tickets WHERE id = ?`, tid).Scan(&domainName, &severity); err != nil {
			return err
		}
		triageDue, remediationDue := s.dueDates(ctx, domainName, severity)
		if _, err := tx.ExecContext(ctx, `UPDATE tickets SET status = 'Waiting to be Triaged', triage_due_date = ?, remediation_due_date = ?, latest_comment = 'False-positive log withdrawn: back on the queue', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, triageDue, remediationDue, tid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, old_value, new_value) VALUES (?, 'Suppression', 'status_change', 'False Positive', 'Waiting to be Triaged')`, tid); err != nil {
			return err
		}
	}
	return tx.Commit()
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
// Every open finding it flags is then raised to Critical, with a fresh clock
// and a history line; raised is how many severities that changed.
func (s *SQLiteStore) SyncCISACatalog(ctx context.Context, feed *domain.CISAFeed) (raised int, err error) {
	defer s.forgetKEV()
	known := make(map[string]bool, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		known[strings.ToUpper(v.CVEID)] = true
	}

	// One pass: which findings name a catalog CVE
	rows, err := s.DB.QueryContext(ctx, `SELECT id, title, description FROM tickets WHERE title LIKE '%CVE-%' OR description LIKE '%CVE-%'`)
	if err != nil {
		return 0, err
	}
	var hits []int
	for rows.Next() {
		var id int
		var title string
		var desc sql.NullString
		if err := rows.Scan(&id, &title, &desc); err != nil {
			rows.Close()
			return 0, err
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
		return 0, err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM cisa_catalog"); err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cisa_catalog (cve_id, date_added) VALUES (?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, v := range feed.Vulnerabilities {
		if _, err := stmt.ExecContext(ctx, v.CVEID, v.DateAdded); err != nil {
			return 0, err
		}
	}

	if _, err := tx.ExecContext(ctx, "UPDATE tickets SET is_cisa_kev = 0 WHERE is_cisa_kev = 1"); err != nil {
		return 0, err
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
			return 0, err
		}
	}
	if raised, err = s.rescoreOpen(ctx, tx, hits, "KEV sync"); err != nil {
		return 0, err
	}
	return raised, tx.Commit()
}

// KEVCatalogStatus reports the loaded catalog: how many CVEs, the newest
// entry, and how many open findings it flags.
func (s *SQLiteStore) KEVCatalogStatus(ctx context.Context) (domain.KEVStatus, error) {
	var st domain.KEVStatus
	var last sql.NullString
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*), MAX(date_added) FROM cisa_catalog`).Scan(&st.Loaded, &last); err != nil {
		return st, err
	}
	st.LastAdded = last.String
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM tickets WHERE is_cisa_kev = 1 AND status NOT IN ('Patched', 'Risk Accepted', 'False Positive')`).Scan(&st.FlaggedOpen)
	return st, err
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
