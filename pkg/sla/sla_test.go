package sla_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/sla"
)

// These tests exercise the real sla.DefaultSLACalculator (not a local copy of
// it): the business-day math, the severity-to-due-date mapping, and the
// true-active-business-hours calculation against a real SQLite store.

func newCalc(holidays ...string) *sla.DefaultSLACalculator {
	h := make(map[string]bool)
	for _, d := range holidays {
		h[d] = true
	}
	return &sla.DefaultSLACalculator{
		Timezone:      "UTC",
		BusinessStart: 9,
		BusinessEnd:   17,
		Holidays:      h,
	}
}

func TestAddBusinessDays(t *testing.T) {
	calc := newCalc()

	cases := []struct {
		name  string
		start string // a weekday/weekend anchor
		add   int
		want  string
	}{
		{"Friday +1 lands on Monday", "2026-01-02", 1, "2026-01-05"}, // Fri -> skip Sat/Sun -> Mon
		{"Monday +5 lands next Monday", "2026-01-05", 5, "2026-01-12"},
		{"Thursday +1 is Friday (no skip)", "2026-01-08", 1, "2026-01-09"},
		{"Saturday +1 is Monday", "2026-01-03", 1, "2026-01-05"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, _ := time.Parse("2006-01-02", tc.start)
			got := calc.AddBusinessDays(start, tc.add).Format("2006-01-02")
			if got != tc.want {
				t.Errorf("AddBusinessDays(%s, %d) = %s, want %s", tc.start, tc.add, got, tc.want)
			}
		})
	}

	t.Run("holidays are skipped like weekends", func(t *testing.T) {
		// Mon 2026-01-05 +1 would normally be Tue 2026-01-06; mark Tue a holiday,
		// so it must roll to Wed 2026-01-07.
		holidayCalc := newCalc("2026-01-06")
		start, _ := time.Parse("2006-01-02", "2026-01-05")
		got := holidayCalc.AddBusinessDays(start, 1).Format("2006-01-02")
		if got != "2026-01-07" {
			t.Errorf("expected the holiday to be skipped to 2026-01-07, got %s", got)
		}
	})
}

func TestCalculateDueDate(t *testing.T) {
	calc := newCalc()

	t.Run("more severe findings are due sooner", func(t *testing.T) {
		crit := calc.CalculateDueDate("Critical")
		high := calc.CalculateDueDate("High")
		med := calc.CalculateDueDate("Medium")
		low := calc.CalculateDueDate("Low")

		if !(crit.Before(*high) && high.Before(*med) && med.Before(*low)) {
			t.Errorf("expected Critical < High < Medium < Low, got %v / %v / %v / %v", crit, high, med, low)
		}
	})

	t.Run("an unknown severity defaults to the Medium window", func(t *testing.T) {
		unknown := calc.CalculateDueDate("Bogus")
		med := calc.CalculateDueDate("Medium")
		if unknown.Format("2006-01-02") != med.Format("2006-01-02") {
			t.Errorf("expected unknown severity to match Medium (%s), got %s",
				med.Format("2006-01-02"), unknown.Format("2006-01-02"))
		}
	})

	t.Run("the due date never lands on a weekend", func(t *testing.T) {
		for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
			due := calc.CalculateDueDate(sev)
			if wd := due.Weekday(); wd == time.Saturday || wd == time.Sunday {
				t.Errorf("%s due date %v fell on a %v", sev, due, wd)
			}
		}
	})
}

func TestCalculateTrueSLAHours(t *testing.T) {
	ctx := context.Background()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "sla.db"))
	defer db.Close()
	store := datastore.NewSQLiteStore(db)

	if err := store.UpdateAppConfig(ctx, domain.AppConfig{Timezone: "UTC", BusinessStart: 9, BusinessEnd: 17}); err != nil {
		t.Fatalf("UpdateAppConfig: %v", err)
	}

	calc := newCalc()

	// backdate forces a ticket's created_at / patched_at to a known window so we
	// can assert exact business-hour math (CreateTicket always stamps "now").
	backdate := func(t *testing.T, created, patched string) int {
		t.Helper()
		tk := &domain.Ticket{Source: "Test", AssetIdentifier: "host-a", Title: "finding " + created, Severity: "High"}
		if err := store.CreateTicket(ctx, tk); err != nil {
			t.Fatalf("CreateTicket: %v", err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE tickets SET created_at = ?, patched_at = ? WHERE id = ?`, created, patched, tk.ID); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		return tk.ID
	}

	t.Run("a 3-hour weekday window inside business hours counts fully", func(t *testing.T) {
		id := backdate(t, "2026-01-05 09:00:00", "2026-01-05 12:00:00") // Monday 09:00->12:00
		hours, err := calc.CalculateTrueSLAHours(ctx, id, store)
		if err != nil {
			t.Fatalf("CalculateTrueSLAHours: %v", err)
		}
		if hours != 3 {
			t.Errorf("expected 3 business hours, got %v", hours)
		}
	})

	t.Run("after-hours and overnight time is not counted", func(t *testing.T) {
		id := backdate(t, "2026-01-05 16:00:00", "2026-01-06 10:00:00") // Mon 16:00 -> Tue 10:00
		hours, err := calc.CalculateTrueSLAHours(ctx, id, store)
		if err != nil {
			t.Fatalf("CalculateTrueSLAHours: %v", err)
		}
		if hours != 2 { // Mon 16-17 (1h) + Tue 09-10 (1h)
			t.Errorf("expected 2 business hours, got %v", hours)
		}
	})

	t.Run("a weekend contributes zero business hours", func(t *testing.T) {
		id := backdate(t, "2026-01-03 09:00:00", "2026-01-04 17:00:00") // all day Sat -> Sun
		hours, err := calc.CalculateTrueSLAHours(ctx, id, store)
		if err != nil {
			t.Fatalf("CalculateTrueSLAHours: %v", err)
		}
		if hours != 0 {
			t.Errorf("expected 0 business hours across a weekend, got %v", hours)
		}
	})
}
