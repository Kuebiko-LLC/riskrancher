package datastore

import (
	"context"
	"testing"
	"time"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// A ticket's clocks come from the SLA matrix for its domain and severity, on
// every creation path, never from a hardcoded number.
func TestCreateTicket_DueDatesComeFromSLAMatrix(t *testing.T) {
	store := NewSQLiteStore(InitDB(":memory:"))
	defer store.DB.Close()
	ctx := context.Background()

	// Given a matrix where a High in the Vulnerability domain remediates in 30 days
	if _, err := store.DB.Exec(`DELETE FROM sla_policies`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO sla_policies (domain, severity, days_to_triage, days_to_remediate, max_extensions) VALUES ('Vulnerability', 'High', 5, 30, 2)`); err != nil {
		t.Fatal(err)
	}

	// When a High is created directly (not through the scanner ingest)
	tk := &domain2.Ticket{Domain: "Vulnerability", Source: "Manual", AssetIdentifier: "host-1", Title: "weak cipher", Severity: "High", Status: "Waiting to be Triaged"}
	if err := store.CreateTicket(ctx, tk); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Then its clocks match the matrix, not a constant
	var triage, remediate time.Time
	if err := store.DB.QueryRow(`SELECT triage_due_date, remediation_due_date FROM tickets WHERE id = ?`, tk.ID).Scan(&triage, &remediate); err != nil {
		t.Fatal(err)
	}
	if d := int(time.Until(remediate).Hours()/24 + 0.5); d != 30 {
		t.Fatalf("remediation clock should be 30 days from the matrix, got %d", d)
	}
	if d := int(time.Until(triage).Hours()/24 + 0.5); d != 5 {
		t.Fatalf("triage clock should be 5 days from the matrix, got %d", d)
	}
}

// A ticket with no clock set is still shown in the pen; it is never silently dropped.
func TestGetDashboardTickets_KeepsRowsWithoutDueDates(t *testing.T) {
	store := NewSQLiteStore(InitDB(":memory:"))
	defer store.DB.Close()

	if _, err := store.DB.Exec(`INSERT INTO tickets (source, asset_identifier, title, severity, description, status, dedupe_hash) VALUES ('Scan', 'host-x', 'no clock', 'Low', 'd', 'Waiting to be Triaged', 'h-noclock')`); err != nil {
		t.Fatal(err)
	}
	tickets, total, _, err := store.GetDashboardTickets(context.Background(), "holding_pen", "", "", "", "RangeHand", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(tickets) != 1 {
		t.Fatalf("the clockless ticket must still be listed: total=%d listed=%d", total, len(tickets))
	}
	if tickets[0].SLAString == "" {
		t.Fatalf("a clockless ticket should say so instead of showing nothing")
	}
}
