package datastore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

// A proposal moves Pending -> Accepted | Contested, and Contested -> Resolved.
// Acting on the wrong state must be rejected, not silently re-applied.
func TestProposalStateMachine(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	// Each sub-test uses its own finding, since only one open proposal is allowed
	// per finding.
	t.Run("accept only works once (second accept is rejected)", func(t *testing.T) {
		tid := seedBHFinding(t, store, "bh@ranch.com", "Critical")
		p, _ := store.ProposeSeverityChange(ctx, tid, "Low", "x", "rh@ranch.com")
		if err := store.AcceptSeverityProposal(ctx, p.ID, "bh@ranch.com"); err != nil {
			t.Fatalf("first accept: %v", err)
		}
		if err := store.AcceptSeverityProposal(ctx, p.ID, "bh@ranch.com"); !errors.Is(err, datastore.ErrProposalNotPending) {
			t.Errorf("expected ErrProposalNotPending re-accepting, got %v", err)
		}
	})

	t.Run("adjudicate requires a contested proposal", func(t *testing.T) {
		tid := seedBHFinding(t, store, "bh@ranch.com", "Critical")
		p, _ := store.ProposeSeverityChange(ctx, tid, "Low", "x", "rh@ranch.com")
		// still Pending, not Contested
		if err := store.AdjudicateSeverityProposal(ctx, p.ID, "High", "sheriff@ranch.com", "n"); !errors.Is(err, datastore.ErrProposalNotContested) {
			t.Errorf("expected ErrProposalNotContested adjudicating a Pending proposal, got %v", err)
		}
	})

	t.Run("contest requires a pending proposal", func(t *testing.T) {
		tid := seedBHFinding(t, store, "bh@ranch.com", "Critical")
		p, _ := store.ProposeSeverityChange(ctx, tid, "Low", "x", "rh@ranch.com")
		store.AcceptSeverityProposal(ctx, p.ID, "bh@ranch.com")
		if err := store.ContestSeverityProposal(ctx, p.ID, "bh@ranch.com", "wait"); !errors.Is(err, datastore.ErrProposalNotPending) {
			t.Errorf("expected ErrProposalNotPending contesting a resolved proposal, got %v", err)
		}
	})
}

// EngagementOwnerForProposal resolves who owns the engagement a proposal's
// finding belongs to, so the handler can enforce owner-only accept/contest.
func TestEngagementOwnerForProposal(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tid := seedBHFinding(t, store, "owner@ranch.com", "High")
	p, _ := store.ProposeSeverityChange(ctx, tid, "Low", "x", "rh@ranch.com")

	owner, err := store.EngagementOwnerForProposal(ctx, p.ID)
	if err != nil {
		t.Fatalf("EngagementOwnerForProposal: %v", err)
	}
	if owner != "owner@ranch.com" {
		t.Errorf("expected owner@ranch.com, got %q", owner)
	}
}
