package datastore_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

// The System Logs tab asks for a page and a filter; the feed honors both.
func TestPaginatedActivityFeed_PagesAndFilters(t *testing.T) {
	s := datastore.NewSQLiteStore(datastore.InitDB(filepath.Join(t.TempDir(), "a.db")))
	defer s.DB.Close()
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		actor := "sheriff@rr.test"
		if i%5 == 0 {
			actor = "dana@rr.test"
		}
		if err := s.LogAuditAction(ctx, actor, "PATCH", "/api/tickets/1", 200, "", "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	page1, total, err := s.GetPaginatedActivityFeed(ctx, "", 15, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 20 || len(page1) != 15 {
		t.Fatalf("page 1 of 20 entries at 15 a page: total=%d got=%d", total, len(page1))
	}
	page2, _, _ := s.GetPaginatedActivityFeed(ctx, "", 15, 15)
	if len(page2) != 5 {
		t.Fatalf("page 2 should hold the remaining 5, got %d", len(page2))
	}
	dana, total, _ := s.GetPaginatedActivityFeed(ctx, "dana", 15, 0)
	if total != 4 || len(dana) != 4 {
		t.Fatalf("filter by actor: total=%d got=%d", total, len(dana))
	}
	if dana[0].Actor != "dana@rr.test" || dana[0].ActivityType == "" {
		t.Fatalf("feed rows should carry actor and action, got %+v", dana[0])
	}
}
