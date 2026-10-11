package storage_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func newEngStore(t *testing.T) (*storage.ProSQLiteStore, func()) {
	t.Helper()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "eng.db"))
	storage.InjectProSchema(db)
	return storage.NewProSQLiteStore(db), func() { db.Close() }
}

func TestCreateEngagementAutoNumbers(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	first := &proModels.Engagement{Name: "Acme External", Client: "Acme", OwnerEmail: "hunter@acme.test"}
	id1, err := store.CreateEngagement(ctx, first)
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	if id1 == 0 || first.ID != id1 {
		t.Fatalf("expected id set on struct, got id=%d struct=%d", id1, first.ID)
	}
	if first.Number != "ENG-0001" {
		t.Errorf("expected first engagement ENG-0001, got %q", first.Number)
	}
	if first.Status != "Active" {
		t.Errorf("expected a new engagement to default to Active, got %q", first.Status)
	}

	second := &proModels.Engagement{Name: "Beta Internal", Client: "Beta", OwnerEmail: "hunter@acme.test"}
	if _, err := store.CreateEngagement(ctx, second); err != nil {
		t.Fatalf("CreateEngagement 2: %v", err)
	}
	if second.Number != "ENG-0002" {
		t.Errorf("expected second engagement ENG-0002, got %q", second.Number)
	}
}

func TestGetAndListEngagements(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	a := &proModels.Engagement{Name: "A", Client: "ClientA", OwnerEmail: "h1@test"}
	b := &proModels.Engagement{Name: "B", Client: "ClientB", OwnerEmail: "h2@test"}
	store.CreateEngagement(ctx, a)
	store.CreateEngagement(ctx, b)

	got, err := store.GetEngagement(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetEngagement: %v", err)
	}
	if got.Name != "A" || got.Client != "ClientA" || got.OwnerEmail != "h1@test" || got.Number != "ENG-0001" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	list, err := store.ListEngagements(ctx)
	if err != nil {
		t.Fatalf("ListEngagements: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 engagements, got %d", len(list))
	}
	if list[0].ID != b.ID {
		t.Errorf("expected newest-first ordering (B before A)")
	}
}

func TestEngagementFindingsLink(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	eng := &proModels.Engagement{Name: "Pentest", Client: "Acme", OwnerEmail: "hunter@acme.test"}
	store.CreateEngagement(ctx, eng)

	// Two findings ingested by the bounty hunter during this engagement.
	t1 := &coredomain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
	t2 := &coredomain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "IDOR", Severity: "Critical", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, t1)
	store.CreateTicket(ctx, t2)

	if err := store.AddFindingsToEngagement(ctx, eng.ID, []int{t1.ID, t2.ID}); err != nil {
		t.Fatalf("AddFindingsToEngagement: %v", err)
	}

	findings, err := store.ListEngagementFindings(ctx, eng.ID)
	if err != nil {
		t.Fatalf("ListEngagementFindings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings linked, got %d", len(findings))
	}
	// A finding not added to the engagement must not appear.
	other := &coredomain.Ticket{Source: "Nessus", AssetIdentifier: "host", Title: "Old TLS", Severity: "Low", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, other)
	findings2, _ := store.ListEngagementFindings(ctx, eng.ID)
	if len(findings2) != 2 {
		t.Errorf("unlinked finding leaked into the engagement, got %d", len(findings2))
	}
}
