package storage_test

import (
	"context"
	"testing"

	coredomain "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

func TestEvidenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tk := &coredomain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, tk)

	web := []byte("WEB-IMAGE-BYTES")
	thumb := []byte("THUMB")
	ev := &proModels.Evidence{
		TicketID: tk.ID, Caption: "login page popup", ContentType: "image/png",
		Width: 800, Height: 600, Size: len(web), CreatedBy: "bh@ranch.com",
	}
	id, err := store.AddEvidence(ctx, ev, web, thumb)
	if err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	if id == 0 || ev.ID != id {
		t.Fatalf("expected id set, got id=%d ev.ID=%d", id, ev.ID)
	}

	list, err := store.ListEvidenceForTicket(ctx, tk.ID)
	if err != nil {
		t.Fatalf("ListEvidenceForTicket: %v", err)
	}
	if len(list) != 1 || list[0].Caption != "login page popup" || list[0].Width != 800 {
		t.Fatalf("unexpected list: %+v", list)
	}

	data, ct, err := store.GetEvidenceBlob(ctx, id, false)
	if err != nil {
		t.Fatalf("GetEvidenceBlob web: %v", err)
	}
	if string(data) != "WEB-IMAGE-BYTES" || ct != "image/png" {
		t.Errorf("web blob mismatch: %q %q", data, ct)
	}
	td, _, err := store.GetEvidenceBlob(ctx, id, true)
	if err != nil || string(td) != "THUMB" {
		t.Errorf("thumb blob mismatch: %q (%v)", td, err)
	}

	meta, err := store.GetEvidenceMeta(ctx, id)
	if err != nil || meta.TicketID != tk.ID {
		t.Errorf("GetEvidenceMeta: %+v (%v)", meta, err)
	}

	if err := store.DeleteEvidence(ctx, id); err != nil {
		t.Fatalf("DeleteEvidence: %v", err)
	}
	after, _ := store.ListEvidenceForTicket(ctx, tk.ID)
	if len(after) != 0 {
		t.Errorf("expected no evidence after delete, got %d", len(after))
	}
}

func TestEngagementOwnerForTicket(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	eng := &proModels.Engagement{Name: "P", OwnerEmail: "owner@ranch.com"}
	store.CreateEngagement(ctx, eng)
	tk := &coredomain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "x", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, tk)
	store.AddFindingsToEngagement(ctx, eng.ID, []int{tk.ID})

	owner, err := store.EngagementOwnerForTicket(ctx, tk.ID)
	if err != nil {
		t.Fatalf("EngagementOwnerForTicket: %v", err)
	}
	if owner != "owner@ranch.com" {
		t.Errorf("expected owner@ranch.com, got %q", owner)
	}
}
