package domain_test

import (
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func bookRubric(t *testing.T) *domain.Rubric {
	t.Helper()
	weights := []domain.RubricWeight{
		{Kind: "base", Key: "Critical", Weight: 4}, {Kind: "base", Key: "High", Weight: 3}, {Kind: "base", Key: "Medium", Weight: 2}, {Kind: "base", Key: "Low", Weight: 1}, {Kind: "base", Key: "Info", Weight: 0},
		{Kind: "exposure", Key: "internet", Weight: 2}, {Kind: "exposure", Key: "internal", Weight: 1}, {Kind: "exposure", Key: "isolated", Weight: 0.5},
		{Kind: "criticality", Key: "crown-jewel", Weight: 2}, {Kind: "criticality", Key: "standard", Weight: 1}, {Kind: "criticality", Key: "dev", Weight: 0.5},
		{Kind: "band", Key: "Critical", Weight: 12}, {Kind: "band", Key: "High", Weight: 6}, {Kind: "band", Key: "Medium", Weight: 3},
	}
	r, ok := domain.NewRubric(weights)
	if !ok {
		t.Fatal("the book's fourteen weights make a rubric")
	}
	return r
}

// The tool scores exactly the way chapter six does by hand.
func TestRubric_ScoresLikeTheBook(t *testing.T) {
	r := bookRubric(t)
	cases := []struct {
		sev, exp, crit string
		score          float64
		band           string
	}{
		{"High", "internet", "crown-jewel", 12, "Critical"},
		{"Critical", "internet", "crown-jewel", 16, "Critical"},
		{"High", "internal", "standard", 3, "Medium"},
		{"Medium", "internet", "standard", 4, "Medium"},
		{"Medium", "internal", "crown-jewel", 4, "Medium"},
		{"Critical", "internal", "crown-jewel", 8, "High"},
		{"Low", "isolated", "dev", 0.25, "Low"},
		{"Critical", "isolated", "dev", 1, "Low"},
		{"Info", "internet", "crown-jewel", 0, "Info"},
	}
	for _, c := range cases {
		score, band, ok := r.Score(c.sev, c.exp, c.crit)
		if !ok || score != c.score || band != c.band {
			t.Errorf("%s x %s x %s = %v %s (ok=%v), want %v %s", c.sev, c.exp, c.crit, score, band, ok, c.score, c.band)
		}
	}
	if _, _, ok := r.Score("High", "dmz", "standard"); ok {
		t.Error("an exposure outside the scale is not scored")
	}
	if _, _, ok := r.Score("Weird", "internet", "standard"); ok {
		t.Error("a severity with no base weight is not scored")
	}
}

func TestNewRubric_FailsClosedWhenAKeyIsMissing(t *testing.T) {
	weights := []domain.RubricWeight{{Kind: "base", Key: "High", Weight: 3}}
	if _, ok := domain.NewRubric(weights); ok {
		t.Fatal("an incomplete rubric must not be applied")
	}
}
