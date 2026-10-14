package adapters

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

// The shipped Trivy adapter must ingest the shipped Trivy sample: its findings
// path walks into an array (Results.0.Vulnerabilities), which a path of map keys
// alone cannot do.
func TestShippedTrivyAdapterIngestsShippedSample(t *testing.T) {
	raw, err := os.ReadFile("../../examples/trivy-sample.json")
	if err != nil {
		t.Skip("sample not present:", err)
	}
	db := datastore.InitDB(":memory:") // seeds the default adapters
	defer db.Close()
	h := NewHandler(datastore.NewSQLiteStore(db))

	req := httptest.NewRequest(http.MethodPost, "/api/ingest/Trivy%20Container%20Scan", bytes.NewReader(raw))
	req.SetPathValue("name", "Trivy Container Scan")
	rec := httptest.NewRecorder()
	h.HandleAdapterIngest(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 from the shipped adapter on the shipped sample, got %d: %s", rec.Code, rec.Body.String())
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM tickets`).Scan(&n)
	if n == 0 {
		t.Fatalf("expected tickets from the sample, got 0")
	}
	// Trivy spells it CRITICAL; the store, the matrix and the counts say Critical
	var criticals int
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE severity = 'Critical'`).Scan(&criticals)
	if criticals != 1 {
		t.Fatalf("the sample has one CRITICAL; stored as Critical: %d", criticals)
	}
	analytics, err := datastore.NewSQLiteStore(db).GetSheriffAnalytics(context.Background())
	if err != nil || analytics.OpenCriticals != 1 {
		t.Fatalf("the metrics page must count it: open criticals=%d err=%v", analytics.OpenCriticals, err)
	}
	t.Logf("ingested %d findings from the sample", n)
}
