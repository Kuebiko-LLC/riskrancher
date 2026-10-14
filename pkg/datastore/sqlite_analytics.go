package datastore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (s *SQLiteStore) GetSheriffAnalytics(ctx context.Context) (domain2.SheriffAnalytics, error) {
	var metrics domain2.SheriffAnalytics

	s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tickets WHERE is_cisa_kev = 1 AND status NOT IN ('Patched', 'Risk Accepted', 'False Positive')").Scan(&metrics.ActiveKEVs)
	s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tickets WHERE severity = 'Critical' AND status NOT IN ('Patched', 'Risk Accepted', 'False Positive')").Scan(&metrics.OpenCriticals)
	s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tickets WHERE remediation_due_date < CURRENT_TIMESTAMP AND status NOT IN ('Patched', 'Risk Accepted', 'False Positive')").Scan(&metrics.TotalOverdue)

	mttrQuery := `
       SELECT COALESCE(AVG(julianday(t.patched_at) - julianday(t.created_at)), 0)
       FROM tickets t
       WHERE t.status = 'Patched' 
    `
	var mttrFloat float64
	s.DB.QueryRowContext(ctx, mttrQuery).Scan(&mttrFloat)
	metrics.GlobalMTTRDays = int(mttrFloat)

	sourceQuery := `
       SELECT 
            t.source,
            SUM(CASE WHEN t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive') THEN 1 ELSE 0 END) as total_open,
            SUM(CASE WHEN t.severity = 'Critical' AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive') THEN 1 ELSE 0 END) as criticals,
            SUM(CASE WHEN t.is_cisa_kev = 1 AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive') THEN 1 ELSE 0 END) as cisa_kevs,
            SUM(CASE WHEN t.status = 'Waiting to be Triaged' THEN 1 ELSE 0 END) as untriaged,
            SUM(CASE WHEN t.remediation_due_date < CURRENT_TIMESTAMP AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive') THEN 1 ELSE 0 END) as patch_overdue,
            SUM(CASE WHEN t.status = 'Pending Risk Approval' THEN 1 ELSE 0 END) as pending_risk,
            
            SUM(CASE WHEN t.status IN ('Patched', 'Risk Accepted', 'False Positive') THEN 1 ELSE 0 END) as total_closed,
            SUM(CASE WHEN t.status = 'Patched' THEN 1 ELSE 0 END) as patched,
            SUM(CASE WHEN t.status = 'Risk Accepted' THEN 1 ELSE 0 END) as risk_accepted,
            SUM(CASE WHEN t.status = 'False Positive' THEN 1 ELSE 0 END) as false_positive
        FROM tickets t
        GROUP BY t.source
        ORDER BY criticals DESC, patch_overdue DESC
    `
	rows, err := s.DB.QueryContext(ctx, sourceQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sm domain2.SourceMetrics
			rows.Scan(&sm.Source, &sm.TotalOpen, &sm.Criticals, &sm.CisaKEVs, &sm.Untriaged, &sm.PatchOverdue, &sm.PendingRisk, &sm.TotalClosed, &sm.Patched, &sm.RiskAccepted, &sm.FalsePositive)

			topAssigneeQ := `
             SELECT COALESCE(ta.assignee, 'Unassigned'), COUNT(t.id) as c
             FROM tickets t LEFT JOIN ticket_assignments ta ON t.id = ta.ticket_id
             WHERE t.source = ? AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive')
             GROUP BY ta.assignee ORDER BY c DESC LIMIT 1`

			var assignee string
			var count int
			s.DB.QueryRowContext(ctx, topAssigneeQ, sm.Source).Scan(&assignee, &count)
			if count > 0 {
				sm.TopAssignee = fmt.Sprintf("%s (%d)", assignee, count)
			} else {
				sm.TopAssignee = "N/A"
			}

			if sm.PatchOverdue > 0 {
				sm.StrategicNote = "🚨 SLA Breach (Escalate to IT Managers)"
			} else if sm.Untriaged > 0 {
				sm.StrategicNote = "⚠️ Triage Bottleneck (Check Analysts)"
			} else if sm.PendingRisk > 0 {
				sm.StrategicNote = "⚖️ Blocked by Exec Adjudication"
			} else if sm.Criticals > 0 {
				sm.StrategicNote = "🔥 High Risk (Monitor closely)"
			} else if sm.RiskAccepted > sm.Patched && sm.TotalClosed > 0 {
				sm.StrategicNote = "👀 High Risk Acceptance Rate (Audit Required)"
			} else if sm.FalsePositive > sm.Patched && sm.TotalClosed > 0 {
				sm.StrategicNote = "🔧 Noisy Source (Scanner needs tuning)"
			} else if sm.TotalClosed > 0 {
				sm.StrategicNote = "✅ Healthy Resolution Velocity"
			} else {
				sm.StrategicNote = "✅ Routine Processing"
			}

			metrics.SourceHealth = append(metrics.SourceHealth, sm)
		}
	}

	sevQuery := `SELECT severity, COUNT(id) FROM tickets WHERE status NOT IN ('Patched', 'Risk Accepted', 'False Positive') GROUP BY severity`
	rowsSev, err := s.DB.QueryContext(ctx, sevQuery)
	if err == nil {
		defer rowsSev.Close()
		for rowsSev.Next() {
			var sev string
			var count int
			rowsSev.Scan(&sev, &count)
			metrics.Severity.Total += count
			switch sev {
			case "Critical":
				metrics.Severity.Critical = count
			case "High":
				metrics.Severity.High = count
			case "Medium":
				metrics.Severity.Medium = count
			case "Low":
				metrics.Severity.Low = count
			case "Info":
				metrics.Severity.Info = count
			}
		}
		if metrics.Severity.Total > 0 {
			metrics.Severity.CritPct = int((float64(metrics.Severity.Critical) / float64(metrics.Severity.Total)) * 100)
			metrics.Severity.HighPct = int((float64(metrics.Severity.High) / float64(metrics.Severity.Total)) * 100)
			metrics.Severity.MedPct = int((float64(metrics.Severity.Medium) / float64(metrics.Severity.Total)) * 100)
			metrics.Severity.LowPct = int((float64(metrics.Severity.Low) / float64(metrics.Severity.Total)) * 100)
			metrics.Severity.InfoPct = int((float64(metrics.Severity.Info) / float64(metrics.Severity.Total)) * 100)
		}
	}

	resQuery := `SELECT status, COUNT(id) FROM tickets WHERE status IN ('Patched', 'Risk Accepted', 'False Positive') GROUP BY status`
	rowsRes, err := s.DB.QueryContext(ctx, resQuery)
	if err == nil {
		defer rowsRes.Close()
		for rowsRes.Next() {
			var status string
			var count int
			rowsRes.Scan(&status, &count)
			metrics.Resolution.Total += count

			switch status {
			case "Patched":
				metrics.Resolution.Patched = count
			case "Risk Accepted":
				metrics.Resolution.RiskAccepted = count
			case "False Positive":
				metrics.Resolution.FalsePositive = count
			}
		}

		if metrics.Resolution.Total > 0 {
			metrics.Resolution.PatchedPct = int((float64(metrics.Resolution.Patched) / float64(metrics.Resolution.Total)) * 100)
			metrics.Resolution.RiskAccPct = int((float64(metrics.Resolution.RiskAccepted) / float64(metrics.Resolution.Total)) * 100)
			metrics.Resolution.FalsePosPct = int((float64(metrics.Resolution.FalsePositive) / float64(metrics.Resolution.Total)) * 100)
		}
	}

	assetQuery := `SELECT asset_identifier, COUNT(id) as c FROM tickets WHERE status NOT IN ('Patched', 'Risk Accepted', 'False Positive') GROUP BY asset_identifier ORDER BY c DESC LIMIT 5`
	rowsAsset, err := s.DB.QueryContext(ctx, assetQuery)
	if err == nil {
		defer rowsAsset.Close()
		var maxAssetCount int
		for rowsAsset.Next() {
			var am domain2.AssetMetric
			rowsAsset.Scan(&am.Asset, &am.Count)
			if maxAssetCount == 0 {
				maxAssetCount = am.Count
			}
			if maxAssetCount > 0 {
				am.Percentage = int((float64(am.Count) / float64(maxAssetCount)) * 100)
			}
			metrics.TopAssets = append(metrics.TopAssets, am)
		}
	}

	return metrics, nil
}

func (s *SQLiteStore) GetDashboardTickets(ctx context.Context, tabStatus, filter, assetFilter, userEmail, userRole string, limit, offset int) ([]domain2.Ticket, int, map[string]int, error) {
	metrics := map[string]int{
		"critical":     0,
		"overdue":      0,
		"mine":         0,
		"verification": 0,
		"returned":     0,
	}

	scope := ""
	var scopeArgs []any

	if userRole == "Wrangler" {
		scope = ` AND LOWER(t.assignee) = LOWER(?)`
		scopeArgs = append(scopeArgs, userEmail)
	}

	if userRole != "Sheriff" {
		var critCount, overCount, mineCount, verifyCount, returnedCount int

		critQ := "SELECT COUNT(t.id) FROM tickets t WHERE t.released = 1 AND t.severity = 'Critical' AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive')" + scope
		s.DB.QueryRowContext(ctx, critQ, scopeArgs...).Scan(&critCount)
		metrics["critical"] = critCount

		overQ := "SELECT COUNT(t.id) FROM tickets t WHERE t.released = 1 AND t.remediation_due_date < CURRENT_TIMESTAMP AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive')" + scope
		s.DB.QueryRowContext(ctx, overQ, scopeArgs...).Scan(&overCount)
		metrics["overdue"] = overCount

		mineQ := "SELECT COUNT(t.id) FROM tickets t WHERE t.released = 1 AND LOWER(t.assignee) = LOWER(?) AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive')"
		s.DB.QueryRowContext(ctx, mineQ, userEmail).Scan(&mineCount)
		metrics["mine"] = mineCount

		verifyQ := "SELECT COUNT(t.id) FROM tickets t WHERE t.released = 1 AND t.status = 'Pending Verification'" + scope
		s.DB.QueryRowContext(ctx, verifyQ, scopeArgs...).Scan(&verifyCount)
		metrics["verification"] = verifyCount

		retQ := "SELECT COUNT(t.id) FROM tickets t WHERE t.released = 1 AND t.status = 'Returned to Security'" + scope
		s.DB.QueryRowContext(ctx, retQ, scopeArgs...).Scan(&returnedCount)
		metrics["returned"] = returnedCount
	}

	// Hide findings held in an unreleased engagement (released = 0).
	whereQ := " WHERE t.released = 1" + scope
	var args []any
	args = append(args, scopeArgs...)

	if assetFilter != "" {
		whereQ += " AND t.asset_identifier = ?"
		args = append(args, assetFilter)
	}

	if tabStatus == "Waiting to be Triaged" || tabStatus == "holding_pen" {
		whereQ += " AND t.status IN ('Waiting to be Triaged', 'Returned to Security', 'Triaged')"
	} else if tabStatus == "Exceptions" {
		whereQ += " AND t.status NOT IN ('Patched', 'Risk Accepted', 'False Positive')"
	} else if tabStatus == "archives" {
		whereQ += " AND t.status IN ('Patched', 'Risk Accepted', 'False Positive')"
	} else if tabStatus != "" {
		whereQ += " AND t.status = ?"
		args = append(args, tabStatus)
	}

	if filter == "critical" {
		whereQ += " AND t.severity = 'Critical'"
	} else if filter == "overdue" {
		whereQ += " AND t.remediation_due_date < CURRENT_TIMESTAMP"
	} else if filter == "mine" {
		whereQ += " AND LOWER(t.assignee) = LOWER(?)"
		args = append(args, userEmail)
	} else if tabStatus == "archives" && filter != "" && filter != "all" {
		whereQ += " AND t.status = ?"
		args = append(args, filter)
	}

	// Page by asset, not by row. A page holds whole asset groups, the pager
	// counts assets, and a host with two hundred findings never straddles pages.
	// Assets come in name order off the covering index so a page costs the same
	// at a million rows as at thirty; returned-to-security findings sort first
	// within the page.
	var total int
	s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM (SELECT 1 FROM tickets t INDEXED BY idx_tickets_asset_status"+whereQ+" GROUP BY t.asset_identifier)", args...).Scan(&total)

	orderClause := "ORDER BY (CASE WHEN t.status = 'Returned to Security' THEN 0 ELSE 1 END) ASC, t.id DESC"

	query := `
	WITH PagedAssets AS (
		SELECT t.asset_identifier FROM tickets t INDEXED BY idx_tickets_asset_status` + whereQ + `
		GROUP BY t.asset_identifier
		ORDER BY t.asset_identifier
		LIMIT ? OFFSET ?
	)
	SELECT 
		t.id, t.source, t.asset_identifier, t.title, COALESCE(t.description, ''), COALESCE(t.recommended_remediation, ''), t.severity, t.status, 
		t.triage_due_date, t.remediation_due_date, COALESCE(t.patch_evidence, ''), 
		t.assignee as current_assignee,
		t.owner_viewed_at,
		t.updated_at, 
		CAST(julianday(COALESCE(t.patched_at, t.updated_at)) - julianday(t.created_at) AS INTEGER) as days_to_resolve,
		COALESCE(t.latest_comment, '') as latest_comment,
		COALESCE(t.risk_rationale, '') as risk_rationale,
		COALESCE(t.extension_count, 0) as extension_count,
		t.exception_expires_at
	FROM tickets t
	JOIN PagedAssets p ON p.asset_identifier = t.asset_identifier` + whereQ + `
	` + orderClause

	pageArgs := append(append(append([]any{}, args...), limit, offset), args...)
	args = pageArgs

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, metrics, err
	}
	defer rows.Close()

	var tickets []domain2.Ticket
	for rows.Next() {
		var t domain2.Ticket
		var assignee string
		var triageDue, remediationDue, exceptionExpires sql.NullTime

		err := rows.Scan(
			&t.ID, &t.Source, &t.AssetIdentifier, &t.Title, &t.Description,
			&t.RecommendedRemediation, &t.Severity, &t.Status,
			&triageDue, &remediationDue, &t.PatchEvidence,
			&assignee,
			&t.OwnerViewedAt,
			&t.UpdatedAt,
			&t.DaysToResolve,
			&t.LatestComment,
			&t.RiskRationale,
			&t.ExtensionCount,
			&exceptionExpires,
		)

		if err == nil {
			t.Assignee = assignee
			if exceptionExpires.Valid {
				exp := exceptionExpires.Time
				t.ExceptionExpiresAt = &exp
			}
			t.TriageDueDate, t.RemediationDueDate = triageDue.Time, remediationDue.Time
			t.IsOverdue = !t.RemediationDueDate.IsZero() && t.RemediationDueDate.Before(time.Now()) && t.Status != "Patched" && t.Status != "Risk Accepted"

			if tabStatus == "archives" {
				if t.DaysToResolve != nil {
					t.SLAString = fmt.Sprintf("%d days", *t.DaysToResolve)
				} else {
					t.SLAString = "Unknown"
				}
			} else if t.RemediationDueDate.IsZero() {
				t.SLAString = "no clock set"
			} else {
				t.SLAString = t.RemediationDueDate.Format("Jan 02, 2006")
			}

			tickets = append(tickets, t)
		}
	}

	return tickets, total, metrics, nil
}

func (s *SQLiteStore) GetAnalyticsSummary(ctx context.Context) (map[string]int, error) {
	summary := make(map[string]int)

	var total int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM tickets WHERE status != 'Patched' AND status != 'Risk Accepted'`).Scan(&total)
	if err != nil {
		return nil, err
	}
	summary["Total_Open"] = total

	sourceRows, err := s.DB.QueryContext(ctx, `SELECT source, COUNT(*) FROM tickets WHERE status != 'Patched' AND status != 'Risk Accepted' GROUP BY source`)
	if err == nil {
		defer sourceRows.Close()
		for sourceRows.Next() {
			var source string
			var count int
			if err := sourceRows.Scan(&source, &count); err == nil {
				summary["Source_"+source+"_Open"] = count
			}
		}
	}

	sevRows, err := s.DB.QueryContext(ctx, `SELECT severity, COUNT(*) FROM tickets WHERE status != 'Patched' AND status != 'Risk Accepted' GROUP BY severity`)
	if err == nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var sev string
			var count int
			if err := sevRows.Scan(&sev, &count); err == nil {
				summary["Severity_"+sev+"_Open"] = count
			}
		}
	}

	return summary, nil
}

// GetPaginatedActivityFeed is the audit log as the System Logs tab reads it:
// newest first, a page at a time, optionally filtered by actor, action, or target.
func (s *SQLiteStore) GetPaginatedActivityFeed(ctx context.Context, filter string, limit, offset int) ([]domain2.FeedItem, int, error) {
	where := ""
	var args []any
	if filter != "" {
		where = " WHERE actor LIKE ? OR action LIKE ? OR target_resource LIKE ?"
		like := "%" + filter + "%"
		args = append(args, like, like, like)
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT actor, action || ' ' || target_resource, status_code,
		CASE WHEN status_code >= 400 THEN error_details ELSE 'Success' END, created_at
		FROM audit_logs`+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	feed := []domain2.FeedItem{}
	for rows.Next() {
		var item domain2.FeedItem
		var createdAt string
		var statusCode int
		if err := rows.Scan(&item.Actor, &item.ActivityType, &statusCode, &item.NewValue, &createdAt); err != nil {
			return nil, 0, err
		}
		item.TimeAgo = createdAt
		feed = append(feed, item)
	}
	return feed, total, rows.Err()
}
