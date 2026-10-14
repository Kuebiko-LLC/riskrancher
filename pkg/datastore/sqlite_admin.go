package datastore

import (
	"context"
	"time"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (s *SQLiteStore) UpdateAppConfig(ctx context.Context, config domain2.AppConfig) error {
	query := `
		INSERT INTO app_config (id, timezone, business_start, business_end, default_extension_days)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			timezone = excluded.timezone,
			business_start = excluded.business_start,
			business_end = excluded.business_end,
			default_extension_days = excluded.default_extension_days
	`
	_, err := s.DB.ExecContext(ctx, query, config.Timezone, config.BusinessStart, config.BusinessEnd, config.DefaultExtensionDays)
	return err
}

func (s *SQLiteStore) GetAppConfig(ctx context.Context) (domain2.AppConfig, error) {
	var c domain2.AppConfig

	query := `SELECT timezone, business_start, business_end, default_extension_days FROM app_config WHERE id = 1`

	err := s.DB.QueryRowContext(ctx, query).Scan(
		&c.Timezone, &c.BusinessStart, &c.BusinessEnd, &c.DefaultExtensionDays,
	)
	return c, err
}

// buildSLAMap creates a fast 2D lookup table: map[Domain][Severity]Policy
func (s *SQLiteStore) buildSLAMap(ctx context.Context) (map[string]map[string]domain2.SLAPolicy, error) {
	return readSLAMap(ctx, s.DB)
}

// readSLAMap is buildSLAMap through a *sql.DB or a *sql.Tx.
func readSLAMap(ctx context.Context, q queryer) (map[string]map[string]domain2.SLAPolicy, error) {
	policies, err := readSLAPolicies(ctx, q)
	if err != nil {
		return nil, err
	}

	slaMap := make(map[string]map[string]domain2.SLAPolicy)
	for _, p := range policies {
		if slaMap[p.Domain] == nil {
			slaMap[p.Domain] = make(map[string]domain2.SLAPolicy)
		}
		slaMap[p.Domain][p.Severity] = p
	}
	return slaMap, nil
}

// slaDays reads the triage and remediation day counts for a domain and
// severity from the matrix, 3 and 30 when it has no row.
func slaDays(slaMap map[string]map[string]domain2.SLAPolicy, domain, severity string) (triage, remediate int) {
	triage, remediate = 3, 30
	if dMap, ok := slaMap[domain]; ok {
		if policy, ok := dMap[severity]; ok {
			triage, remediate = policy.DaysToTriage, policy.DaysToRemediate
		}
	}
	return
}

// dueDates returns the triage and remediation clocks for a domain and severity
// from the SLA matrix, starting now.
func (s *SQLiteStore) dueDates(ctx context.Context, domain, severity string) (time.Time, time.Time) {
	slaMap, _ := s.buildSLAMap(ctx)
	daysToTriage, daysToRemediate := slaDays(slaMap, domain, severity)
	now := time.Now()
	return now.AddDate(0, 0, daysToTriage), now.AddDate(0, 0, daysToRemediate)
}

func (s *SQLiteStore) ExportSystemState(ctx context.Context) (domain2.ExportState, error) {
	var state domain2.ExportState
	state.Version = "1.1"
	state.ExportedAt = time.Now().UTC().Format(time.RFC3339)

	config, err := s.GetAppConfig(ctx)
	if err == nil {
		state.AppConfig = config
	}

	slas, err := s.GetSLAPolicies(ctx)
	if err == nil {
		state.SLAPolicies = slas
	}

	users, err := s.GetAllUsers(ctx)
	if err == nil {
		for _, u := range users {
			u.PasswordHash = ""
			state.Users = append(state.Users, *u)
		}
	}

	adapters, err := s.GetAdapters(ctx)
	if err == nil {
		state.Adapters = adapters
	}

	query := `SELECT id, domain, source, asset_identifier, title, COALESCE(description, ''), severity, status, dedupe_hash, created_at FROM tickets`
	rows, err := s.DB.QueryContext(ctx, query)
	if err != nil {
		return state, err
	}
	defer rows.Close()

	for rows.Next() {
		var t domain2.Ticket
		if err := rows.Scan(&t.ID, &t.Domain, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description, &t.Severity, &t.Status, &t.DedupeHash, &t.CreatedAt); err == nil {
			state.Tickets = append(state.Tickets, t)
		}
	}

	return state, nil
}

func (s *SQLiteStore) GetSLAPolicies(ctx context.Context) ([]domain2.SLAPolicy, error) {
	return readSLAPolicies(ctx, s.DB)
}

func readSLAPolicies(ctx context.Context, q queryer) ([]domain2.SLAPolicy, error) {
	rows, err := q.QueryContext(ctx, "SELECT domain, severity, days_to_remediate, max_extensions, days_to_triage FROM sla_policies ORDER BY domain, severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []domain2.SLAPolicy
	for rows.Next() {
		var p domain2.SLAPolicy
		rows.Scan(&p.Domain, &p.Severity, &p.DaysToRemediate, &p.MaxExtensions, &p.DaysToTriage)
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *SQLiteStore) UpdateSLAPolicies(ctx context.Context, slas []domain2.SLAPolicy) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		UPDATE sla_policies 
		SET days_to_triage = ?, days_to_remediate = ?, max_extensions = ? 
		WHERE domain = ? AND severity = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, sla := range slas {
		_, err = stmt.ExecContext(ctx, sla.DaysToTriage, sla.DaysToRemediate, sla.MaxExtensions, sla.Domain, sla.Severity)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetWranglers(ctx context.Context) ([]domain2.User, error) {
	query := `
		SELECT id, email, full_name, global_role, is_active, created_at 
		FROM users 
		WHERE global_role = 'Wrangler' AND is_active = 1
		ORDER BY email ASC
	`
	rows, err := s.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wranglers []domain2.User
	for rows.Next() {
		var w domain2.User
		if err := rows.Scan(&w.ID, &w.Email, &w.FullName, &w.GlobalRole, &w.IsActive, &w.CreatedAt); err != nil {
			return nil, err
		}
		wranglers = append(wranglers, w)
	}
	return wranglers, nil
}
