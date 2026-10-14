package storage_test

import (
	"context"
	"fmt"
	"testing"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// seedBHFinding makes an engagement owned by ownerEmail and one finding linked
// to it (so the finding is BH-origin), returning the ticket id.
func seedBHFinding(t *testing.T, store *storage.ProSQLiteStore, ownerEmail, severity string) int {
	t.Helper()
	ctx := context.Background()
	eng := &coredomain.Engagement{Name: "Pentest", Client: "Acme", OwnerEmail: ownerEmail}
	if _, err := store.CreateEngagement(ctx, eng); err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	tk := &coredomain.Ticket{Source: "Burp", AssetIdentifier: fmt.Sprintf("web-e%d", eng.ID), Title: fmt.Sprintf("finding %s e%d", severity, eng.ID), Severity: severity, Status: "Waiting to be Triaged"}
	if err := store.CreateTicket(ctx, tk); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if err := store.AddFindingsToEngagement(ctx, eng.ID, []int{tk.ID}); err != nil {
		t.Fatalf("AddFindingsToEngagement: %v", err)
	}
	return tk.ID
}

func TestProposeSeverityOnlyForBountyHunterFindings(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	// A plain finding with no engagement (not BH-origin).
	plain := &coredomain.Ticket{Source: "Trivy", AssetIdentifier: "host", Title: "plain", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, plain)
	if _, err := store.ProposeSeverityChange(ctx, plain.ID, "Low", "looks lower", "rh@ranch.com"); err == nil {
		t.Errorf("expected an error proposing a severity change on a non-BH finding")
	}

	// A BH-origin finding accepts a proposal.
	tid := seedBHFinding(t, store, "bh@ranch.com", "High")
	p, err := store.ProposeSeverityChange(ctx, tid, "Low", "dev dependency only", "rh@ranch.com")
	if err != nil {
		t.Fatalf("ProposeSeverityChange: %v", err)
	}
	if p.Status != "Pending" || p.FromSeverity != "High" || p.ToSeverity != "Low" {
		t.Errorf("unexpected proposal: %+v", p)
	}

	// The severity must NOT change on a mere proposal.
	got, _ := store.GetTicketByID(ctx, tid)
	if got.Severity != "High" {
		t.Errorf("a proposal must not change severity yet; got %q", got.Severity)
	}

	// History records the proposal.
	hist, _ := store.ListProposalsForTicket(ctx, tid)
	if len(hist) != 1 {
		t.Errorf("expected 1 proposal in history, got %d", len(hist))
	}
}

func TestAcceptSeverityProposalAppliesIt(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tid := seedBHFinding(t, store, "bh@ranch.com", "Critical")
	p, _ := store.ProposeSeverityChange(ctx, tid, "Medium", "compensating control in place", "rh@ranch.com")

	if err := store.AcceptSeverityProposal(ctx, p.ID, "bh@ranch.com"); err != nil {
		t.Fatalf("AcceptSeverityProposal: %v", err)
	}
	got, _ := store.GetTicketByID(ctx, tid)
	if got.Severity != "Medium" {
		t.Errorf("accepting should apply the proposed severity; got %q", got.Severity)
	}
	after, _ := store.GetSeverityProposal(ctx, p.ID)
	if after.Status != "Accepted" {
		t.Errorf("expected Accepted, got %q", after.Status)
	}
}

func TestContestThenSheriffAdjudicates(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tid := seedBHFinding(t, store, "bh@ranch.com", "Critical")
	p, _ := store.ProposeSeverityChange(ctx, tid, "Low", "false positive", "rh@ranch.com")

	// BH contests -> escalated, severity still unchanged.
	if err := store.ContestSeverityProposal(ctx, p.ID, "bh@ranch.com", "this is exploitable in prod"); err != nil {
		t.Fatalf("ContestSeverityProposal: %v", err)
	}
	mid, _ := store.GetSeverityProposal(ctx, p.ID)
	if mid.Status != "Contested" {
		t.Errorf("expected Contested, got %q", mid.Status)
	}
	if got, _ := store.GetTicketByID(ctx, tid); got.Severity != "Critical" {
		t.Errorf("contesting must not change severity; got %q", got.Severity)
	}

	// Sheriff breaks the tie -> applies the final call.
	if err := store.AdjudicateSeverityProposal(ctx, p.ID, "High", "sheriff@ranch.com", "exploitable but mitigated by WAF"); err != nil {
		t.Fatalf("AdjudicateSeverityProposal: %v", err)
	}
	final, _ := store.GetSeverityProposal(ctx, p.ID)
	if final.Status != "Resolved" || final.ResolvedBy != "sheriff@ranch.com" {
		t.Errorf("unexpected resolved proposal: %+v", final)
	}
	if got, _ := store.GetTicketByID(ctx, tid); got.Severity != "High" {
		t.Errorf("adjudication should apply the final severity; got %q", got.Severity)
	}
}

func TestPendingProposalsAlertTheOwningBountyHunter(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	mine := seedBHFinding(t, store, "bh@ranch.com", "High")
	theirs := seedBHFinding(t, store, "other@ranch.com", "High")
	store.ProposeSeverityChange(ctx, mine, "Low", "x", "rh@ranch.com")
	store.ProposeSeverityChange(ctx, theirs, "Low", "y", "rh@ranch.com")

	alerts, err := store.ListPendingProposalsForOwner(ctx, "bh@ranch.com")
	if err != nil {
		t.Fatalf("ListPendingProposalsForOwner: %v", err)
	}
	if len(alerts) != 1 || alerts[0].TicketID != mine {
		t.Errorf("a BH should only be alerted about proposals on their own engagements; got %+v", alerts)
	}
}

func TestContestedProposalsHitTheSheriffQueue(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	a := seedBHFinding(t, store, "bh@ranch.com", "Critical")
	b := seedBHFinding(t, store, "bh@ranch.com", "High")
	pa, _ := store.ProposeSeverityChange(ctx, a, "Low", "fp", "rh@ranch.com")
	store.ProposeSeverityChange(ctx, b, "Low", "fp", "rh@ranch.com")

	// Only pa gets contested; it should be the only thing in the Sheriff queue.
	if err := store.ContestSeverityProposal(ctx, pa.ID, "bh@ranch.com", "exploitable"); err != nil {
		t.Fatalf("ContestSeverityProposal: %v", err)
	}

	queue, err := store.ListContestedProposals(ctx)
	if err != nil {
		t.Fatalf("ListContestedProposals: %v", err)
	}
	if len(queue) != 1 || queue[0].ID != pa.ID {
		t.Errorf("Sheriff queue should hold exactly the contested proposal; got %+v", queue)
	}

	// Once the Sheriff rules, it leaves the queue.
	store.AdjudicateSeverityProposal(ctx, pa.ID, "High", "sheriff@ranch.com", "mitigated")
	queue2, _ := store.ListContestedProposals(ctx)
	if len(queue2) != 0 {
		t.Errorf("a resolved proposal must leave the Sheriff queue; got %d", len(queue2))
	}
}
