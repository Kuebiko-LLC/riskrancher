package datastore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The rules engine runs on every path a finding can arrive by: direct creation
// and scanner batch ingest. A decision made once applies to every row, every scan.
//
// Before the insert: a logged false positive (by finding hash on an asset, or a
// global rule by source/asset/title) lands as False Positive; then the
// severity is decided once, in decideSeverity: the rubric when the asset is in
// the inventory, an explicit severity rule over that, and KEV over everything.
// After the insert: a routing rule hands the new, unassigned findings to their
// owner.

type triageRule struct {
	source, asset, action, value string
}

type ingestRules struct {
	suppressedHashes map[string]bool // dedupe hashes suppressed on this asset
	global           []GlobalSuppressionRule
	triage           []triageRule
	kev              map[string]bool // the loaded KEV catalog, by CVE id
	asset            *domain.Asset   // the inventory row, nil when the asset is not in it
	rubric           *domain.Rubric  // nil when the stored weights are incomplete
}

// loadIngestRules reads the rules once for a batch on one asset.
func (s *SQLiteStore) loadIngestRules(ctx context.Context, asset string) (*ingestRules, error) {
	r := &ingestRules{suppressedHashes: map[string]bool{}, kev: s.kevSet(ctx)}

	rows, err := s.DB.QueryContext(ctx, `SELECT dedupe_hash FROM suppression_rules WHERE asset_identifier = ?`, asset)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil {
			r.suppressedHashes[h] = true
		}
	}
	rows.Close()

	rows, err = s.DB.QueryContext(ctx, `SELECT match_source, match_asset, match_title, rationale FROM global_suppression_rules WHERE is_active = 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g GlobalSuppressionRule
		if err := rows.Scan(&g.MatchSource, &g.MatchAsset, &g.MatchTitle, &g.Rationale); err == nil {
			r.global = append(r.global, g)
		}
	}
	rows.Close()

	if r.triage, err = loadTriageRules(ctx, s.DB); err != nil {
		return nil, err
	}
	if r.asset, err = s.assetByID(ctx, asset); err != nil {
		return nil, err
	}
	r.rubric = loadRubric(ctx, s.DB)
	return r, nil
}

// loadTriageRules reads the severity rules.
func loadTriageRules(ctx context.Context, q queryer) ([]triageRule, error) {
	rows, err := q.QueryContext(ctx, `SELECT COALESCE(match_source,''), COALESCE(match_asset,''), action_type, action_value FROM auto_triage_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []triageRule
	for rows.Next() {
		var t triageRule
		if err := rows.Scan(&t.source, &t.asset, &t.action, &t.value); err == nil {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// loadRubric reads the weights; nil when they do not make a whole rubric.
func loadRubric(ctx context.Context, q queryer) *domain.Rubric {
	weights, err := readRubric(ctx, q)
	if err != nil {
		return nil
	}
	r, ok := domain.NewRubric(weights)
	if !ok {
		return nil
	}
	return r
}

func dedupeHash(source, asset, title string) string {
	sum := sha256.Sum256([]byte(source + "|" + asset + "|" + title))
	return hex.EncodeToString(sum[:])
}

func (g GlobalSuppressionRule) matches(t *domain.Ticket) bool {
	if g.MatchSource.Valid && !strings.EqualFold(t.Source, g.MatchSource.String) {
		return false
	}
	if g.MatchAsset.Valid && !strings.Contains(strings.ToLower(t.AssetIdentifier), strings.ToLower(g.MatchAsset.String)) {
		return false
	}
	if g.MatchTitle.Valid && !strings.Contains(strings.ToLower(t.Title), strings.ToLower(g.MatchTitle.String)) {
		return false
	}
	return true
}

// apply runs the pre-insert rules on one finding.
func (r *ingestRules) apply(t *domain.Ticket) {
	t.Severity = domain.NormalizeSeverity(t.Severity)
	t.ScannerSeverity = t.Severity
	t.IsCISAKEV = r.namesKEV(t.Title + " " + t.Description)
	if t.DedupeHash == "" {
		t.DedupeHash = dedupeHash(t.Source, t.AssetIdentifier, t.Title)
	}
	if r.suppressedHashes[t.DedupeHash] {
		t.Status = "False Positive"
		return
	}
	for _, g := range r.global {
		if g.matches(t) {
			t.Status = "False Positive"
			return
		}
	}
	t.Severity, t.RubricScore = decideSeverity(r.rubric, r.asset, r.triage, t.Source, t.AssetIdentifier, t.ScannerSeverity, t.IsCISAKEV)
}

// namesKEV reports whether the text names a CVE in the loaded catalog.
func (r *ingestRules) namesKEV(text string) bool {
	if len(r.kev) == 0 {
		return false
	}
	for _, m := range cveToken.FindAllString(text, -1) {
		if r.kev[strings.ToUpper(m)] {
			return true
		}
	}
	return false
}

// decideSeverity is the only place a scanner's word becomes a priority: the
// rubric when the asset is in the inventory (the score is recorded either
// way), then an explicit severity rule, then KEV, which is Critical whatever
// the math or a rule says. An asset the tool does not know keeps the
// scanner's word.
func decideSeverity(rb *domain.Rubric, asset *domain.Asset, triage []triageRule, source, assetID, scannerSeverity string, isKEV bool) (severity string, score *float64) {
	severity = scannerSeverity
	if rb != nil && asset != nil {
		if s, band, ok := rb.Score(scannerSeverity, asset.Exposure, asset.Criticality); ok {
			severity, score = band, &s
		}
	}
	for _, rule := range triage {
		if rule.source != "" && rule.source != source {
			continue
		}
		if rule.asset != "" && rule.asset != assetID {
			continue
		}
		if rule.action == "DowngradeSeverity" {
			severity = domain.NormalizeSeverity(rule.value)
		}
	}
	if isKEV {
		severity = "Critical"
	}
	return severity, score
}

// routingTarget returns the owner a routing rule names for this asset or source.
func (s *SQLiteStore) routingTarget(ctx context.Context, source, asset string) (assignee, role string, ok bool) {
	err := s.DB.QueryRowContext(ctx, `
		SELECT assignee, role FROM routing_rules
		WHERE (rule_type = 'Asset' AND match_value = ?) OR (rule_type = 'Source' AND match_value = ?)
		ORDER BY (CASE WHEN rule_type = 'Asset' THEN 1 ELSE 2 END) ASC LIMIT 1`, asset, source).Scan(&assignee, &role)
	return assignee, role, err == nil && assignee != ""
}

// assign hands the given tickets to an owner: the ticket row, the assignment, and the activity log.
func (s *SQLiteStore) assign(ctx context.Context, ids []int, assignee, role string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE tickets SET assignee = ?, status = 'Assigned Out', assigned_at = CURRENT_TIMESTAMP WHERE id = ?`, assignee, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ticket_assignments (ticket_id, role, assignee) VALUES (?, ?, ?)`, id, role, assignee); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ticket_activity (ticket_id, actor, activity_type, new_value) VALUES (?, 'Rules Engine', 'assigned_to', ?)`, id, assignee); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// routeUnassigned applies the routing rule to every open, unassigned finding on
// an asset from a source: the ones this ingest just inserted, and any earlier
// ones nobody had picked up.
func (s *SQLiteStore) routeUnassigned(ctx context.Context, source, asset string) error {
	assignee, role, ok := s.routingTarget(ctx, source, asset)
	if !ok {
		return nil
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM tickets WHERE source = ? AND asset_identifier = ? AND status = 'Waiting to be Triaged' AND assignee = 'Unassigned'`, source, asset)
	if err != nil {
		return err
	}
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	return s.assign(ctx, ids, assignee, role)
}

// CreateTicket runs the rules, inserts, then routes.
func (s *SQLiteStore) CreateTicket(ctx context.Context, ticket *domain.Ticket) error {
	rules, err := s.loadIngestRules(ctx, ticket.AssetIdentifier)
	if err != nil {
		return err
	}
	rules.apply(ticket)
	if err := s.insertTicket(ctx, ticket); err != nil {
		return err
	}
	if ticket.Status == "False Positive" {
		return nil
	}
	if assignee, role, ok := s.routingTarget(ctx, ticket.Source, ticket.AssetIdentifier); ok {
		if err := s.assign(ctx, []int{ticket.ID}, assignee, role); err != nil {
			return err
		}
		ticket.Assignee, ticket.Status = assignee, "Assigned Out"
	}
	return nil
}

// ProcessIngestionBatch runs the rules on every finding, hands the batch to the
// base store (dedup, reopen, autoclose), then routes what is new and unowned.
func (s *SQLiteStore) ProcessIngestionBatch(ctx context.Context, source, asset string, batch []domain.Ticket) error {
	rules, err := s.loadIngestRules(ctx, asset)
	if err != nil {
		return err
	}
	for i := range batch {
		rules.apply(&batch[i])
	}
	if err := s.ingestBatch(ctx, source, asset, batch); err != nil {
		return err
	}
	return s.routeUnassigned(ctx, source, asset)
}
