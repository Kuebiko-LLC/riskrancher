package datastore_test

import (
	"context"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The asset inventory (chapter two of the book) and the priority rubric
// (chapter six) live in the database, so ingest can score a finding against
// the asset it landed on.

func TestAssets_UpsertIsIdempotentAndListIsSorted(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()

	// Given the same asset loaded twice, the second time with a new owner
	first := []domain.Asset{{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel", Owner: "Payments", Notes: "PCI scope"}}
	if err := s.UpsertAssets(ctx, first); err != nil {
		t.Fatal(err)
	}
	again := []domain.Asset{
		{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel", Owner: "Dana", Notes: "PCI scope"},
		{AssetIdentifier: "customer-db", Exposure: "internal", Criticality: "crown-jewel", Owner: "Data"},
	}
	if err := s.UpsertAssets(ctx, again); err != nil {
		t.Fatal(err)
	}

	// Then the list has one row per asset, sorted by name, with the latest values
	got, err := s.ListAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 assets, got %d", len(got))
	}
	if got[0].AssetIdentifier != "customer-db" || got[1].AssetIdentifier != "payments-api" {
		t.Fatalf("not sorted: %s, %s", got[0].AssetIdentifier, got[1].AssetIdentifier)
	}
	if got[1].Owner != "Dana" || got[1].Exposure != "internet" || got[1].Criticality != "crown-jewel" {
		t.Fatalf("latest values not kept: %+v", got[1])
	}
}

func TestAssets_RejectsAValueOutsideTheScale(t *testing.T) {
	s := newRulesStore(t)
	err := s.UpsertAssets(context.Background(), []domain.Asset{{AssetIdentifier: "x", Exposure: "dmz", Criticality: "standard"}})
	if err == nil {
		t.Fatal("exposure 'dmz' should be refused by the schema")
	}
}

func TestRubric_SeededWithTheBooksNumbers(t *testing.T) {
	s := newRulesStore(t)
	got, err := s.GetRubric(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 14 {
		t.Fatalf("want 14 weights, got %d", len(got))
	}
	want := map[string]float64{"base/High": 3, "exposure/isolated": 0.5, "criticality/crown-jewel": 2, "band/Critical": 12, "base/Info": 0}
	seen := map[string]float64{}
	for _, w := range got {
		seen[w.Kind+"/"+w.Key] = w.Weight
	}
	for k, v := range want {
		if seen[k] != v {
			t.Errorf("%s = %v, want %v", k, seen[k], v)
		}
	}
	// Display order: the base severities first, Critical before High
	if got[0].Kind != "base" || got[0].Key != "Critical" || got[1].Key != "High" {
		t.Fatalf("display order wrong: %+v", got[:2])
	}
}

func TestRubric_UpdateChangesOnlyNamedWeights(t *testing.T) {
	s := newRulesStore(t)
	ctx := context.Background()
	if err := s.UpdateRubric(ctx, []domain.RubricWeight{{Kind: "band", Key: "Critical", Weight: 10}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRubric(ctx)
	for _, w := range got {
		switch w.Kind + "/" + w.Key {
		case "band/Critical":
			if w.Weight != 10 {
				t.Errorf("band/Critical = %v, want 10", w.Weight)
			}
		case "band/High":
			if w.Weight != 6 {
				t.Errorf("band/High changed to %v", w.Weight)
			}
		}
	}
}
