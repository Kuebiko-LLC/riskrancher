package storage_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func TestPentestReportRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "reports.db"))
	defer db.Close()
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	in := &proModels.PentestReport{
		Title:            "Q1 Engagement",
		ClientName:       "Acme",
		Author:           "t",
		Scope:            "app.acme.test",
		ExecutiveSummary: "Looks mostly fine.",
		TicketIDs:        []int{4, 8, 15},
		Markdown:         "# Q1 Engagement\n",
		HTML:             "<h1>Q1 Engagement</h1>",
		CreatedBy:        "t@acme.test",
	}

	id, err := store.CreatePentestReport(ctx, in)
	if err != nil {
		t.Fatalf("CreatePentestReport: %v", err)
	}
	if id == 0 || in.ID != id {
		t.Fatalf("expected a non-zero id set on the struct, got id=%d in.ID=%d", id, in.ID)
	}

	got, err := store.GetPentestReport(ctx, id)
	if err != nil {
		t.Fatalf("GetPentestReport: %v", err)
	}
	if got.Title != in.Title || got.Markdown != in.Markdown || got.HTML != in.HTML || got.CreatedBy != in.CreatedBy {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if len(got.TicketIDs) != 3 || got.TicketIDs[0] != 4 || got.TicketIDs[2] != 15 {
		t.Errorf("ticket_ids did not round-trip: %v", got.TicketIDs)
	}

	list, err := store.ListPentestReports(ctx)
	if err != nil {
		t.Fatalf("ListPentestReports: %v", err)
	}
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("expected exactly one listed report with id %d, got %+v", id, list)
	}
	if list[0].Markdown != "" || list[0].HTML != "" {
		t.Errorf("list view should omit the heavy rendered bodies")
	}
}
