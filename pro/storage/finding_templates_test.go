package storage_test

import (
	"context"
	"testing"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

func TestFindingTemplateCRUDAndApply(t *testing.T) {
	ctx := context.Background()
	store, done := newEngStore(t)
	defer done()

	tpl := &proModels.FindingTemplate{
		Name: "Missing security headers", Title: "Missing security headers",
		Severity: "Low", Description: "The application does not set X / Y headers.",
		Remediation: "Add the headers at the edge.", Tags: "headers,web", CreatedBy: "bh@ranch.com",
	}
	id, err := store.CreateFindingTemplate(ctx, tpl)
	if err != nil {
		t.Fatalf("CreateFindingTemplate: %v", err)
	}
	if id == 0 || tpl.ID != id {
		t.Fatalf("expected id set, got %d / %d", id, tpl.ID)
	}

	got, err := store.GetFindingTemplate(ctx, id)
	if err != nil || got.Name != "Missing security headers" || got.Severity != "Low" {
		t.Fatalf("GetFindingTemplate mismatch: %+v (%v)", got, err)
	}
	if list, _ := store.ListFindingTemplates(ctx); len(list) != 1 {
		t.Errorf("expected 1 template, got %d", len(list))
	}

	// update
	got.Title = "Missing security headers (hardened)"
	got.Severity = "Medium"
	if err := store.UpdateFindingTemplate(ctx, got); err != nil {
		t.Fatalf("UpdateFindingTemplate: %v", err)
	}
	if after, _ := store.GetFindingTemplate(ctx, id); after.Title != "Missing security headers (hardened)" || after.Severity != "Medium" {
		t.Errorf("update not persisted: %+v", after)
	}

	// apply to an engagement -> creates a held, prefilled finding
	eng := &proModels.Engagement{Name: "P", OwnerEmail: "bh@ranch.com"}
	store.CreateEngagement(ctx, eng)
	fid, err := store.CreateFindingFromTemplate(ctx, id, eng.ID, "web-app-01", "bh@ranch.com")
	if err != nil {
		t.Fatalf("CreateFindingFromTemplate: %v", err)
	}

	findings, _ := store.ListEngagementFindings(ctx, eng.ID)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on the engagement, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != fid || f.Title != "Missing security headers (hardened)" || f.Severity != "Medium" ||
		f.AssetIdentifier != "web-app-01" || f.RecommendedRemediation == "" {
		t.Errorf("finding not prefilled from template: %+v", f)
	}

	// it must be HELD (released=0), i.e. not in the RangeHand queue yet
	rows, _, _, _ := store.GetDashboardTickets(ctx, "holding_pen", "", "", "rh@ranch.com", "RangeHand", 100, 0)
	for _, r := range rows {
		if r.ID == fid {
			t.Errorf("a template-applied finding must be held until release")
		}
	}

	// delete the template
	if err := store.DeleteFindingTemplate(ctx, id); err != nil {
		t.Fatalf("DeleteFindingTemplate: %v", err)
	}
	if list, _ := store.ListFindingTemplates(ctx); len(list) != 0 {
		t.Errorf("template should be gone after delete")
	}
}
