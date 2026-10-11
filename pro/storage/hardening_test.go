package storage_test

import (
	"context"
	"errors"
	"testing"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// L2: only one open (Pending) severity proposal may exist per finding.
func TestOneOpenProposalPerFinding(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tid := seedBHFinding(t, store, "bh@ranch.com", "High")

	if _, err := store.ProposeSeverityChange(ctx, tid, "Low", "x", "rh@ranch.com"); err != nil {
		t.Fatalf("first proposal: %v", err)
	}
	if _, err := store.ProposeSeverityChange(ctx, tid, "Medium", "y", "rh@ranch.com"); !errors.Is(err, storage.ErrProposalAlreadyOpen) {
		t.Errorf("expected ErrProposalAlreadyOpen on a second open proposal, got %v", err)
	}

	// After the first is resolved, a new proposal is allowed again.
	hist, _ := store.ListProposalsForTicket(ctx, tid)
	store.AcceptSeverityProposal(ctx, hist[0].ID, "bh@ranch.com")
	if _, err := store.ProposeSeverityChange(ctx, tid, "Low", "z", "rh@ranch.com"); err != nil {
		t.Errorf("a new proposal should be allowed once the prior one is resolved, got %v", err)
	}
}

// L4: create responses carry a real created_at.
func TestCreateSetsTimestamps(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	e := &proModels.Engagement{Name: "x", OwnerEmail: "o@ranch.com"}
	store.CreateEngagement(ctx, e)
	if e.CreatedAt.IsZero() {
		t.Errorf("engagement created_at should be populated after create")
	}

	rep := &proModels.PentestReport{Title: "r"}
	store.CreatePentestReport(ctx, rep)
	if rep.CreatedAt.IsZero() {
		t.Errorf("report created_at should be populated after create")
	}
}
