//go:build scale

// This heavyweight scale test (10k assets / 1,000,000 tickets, ~45s) is gated
// behind the `scale` build tag so the default `go test ./...` stays fast.
// Run it explicitly with:  go test -tags scale ./pkg/ingest/
package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestHandleIngest_OneMillionTicketStressTest(t *testing.T) {
	a, db := setupTestIngest(t)
	defer db.Close()

	numAssets := 10000
	vulnsPerAsset := 100

	t.Logf("Generating baseline payload for %d tickets...", numAssets*vulnsPerAsset)

	baselinePayload := make([]domain.Ticket, 0, numAssets*vulnsPerAsset)
	for assetID := 1; assetID <= numAssets; assetID++ {
		assetName := fmt.Sprintf("Server-%05d", assetID)
		for vulnID := 1; vulnID <= vulnsPerAsset; vulnID++ {
			baselinePayload = append(baselinePayload, domain.Ticket{
				Source:          "HeavyLoadTester",
				AssetIdentifier: assetName,
				Title:           fmt.Sprintf("Vulnerability-%03d", vulnID),
				Severity:        "High",
			})
		}
	}

	t.Log("Marshaling 1M tickets to JSON...")
	body1, _ := json.Marshal(baselinePayload)
	req1 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(body1))
	rr1 := httptest.NewRecorder()

	t.Log("Hitting API with Baseline 1M Scan...")
	a.HandleIngest(rr1, req1)

	if rr1.Code != http.StatusCreated {
		t.Fatalf("Baseline ingest failed with status %d", rr1.Code)
	}

	var count1 int
	db.QueryRow(`SELECT COUNT(*) FROM tickets`).Scan(&count1)
	if count1 != 1000000 {
		t.Fatalf("Expected 1,000,000 tickets inserted, got %d", count1)
	}

	t.Log("Generating Diff payload...")

	diffPayload := make([]domain.Ticket, 0, numAssets*vulnsPerAsset)
	for assetID := 1; assetID <= numAssets; assetID++ {
		assetName := fmt.Sprintf("Server-%05d", assetID)

		for vulnID := 1; vulnID <= 80; vulnID++ {
			diffPayload = append(diffPayload, domain.Ticket{
				Source:          "HeavyLoadTester",
				AssetIdentifier: assetName,
				Title:           fmt.Sprintf("Vulnerability-%03d", vulnID),
				Severity:        "High",
			})
		}

		for vulnID := 101; vulnID <= 120; vulnID++ {
			diffPayload = append(diffPayload, domain.Ticket{
				Source:          "HeavyLoadTester",
				AssetIdentifier: assetName,
				Title:           fmt.Sprintf("Vulnerability-%03d", vulnID),
				Severity:        "Critical",
			})
		}
	}

	t.Log("Marshaling Diff payload to JSON...")
	body2, _ := json.Marshal(diffPayload)
	req2 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(body2))
	rr2 := httptest.NewRecorder()

	t.Log("Hitting API with Diff 1M Scan...")
	a.HandleIngest(rr2, req2)

	if rr2.Code != http.StatusCreated {
		t.Fatalf("Diff ingest failed with status %d", rr2.Code)
	}

	t.Log("Running Assertions...")

	var totalRows int
	db.QueryRow(`SELECT COUNT(*) FROM tickets`).Scan(&totalRows)
	if totalRows != 1200000 {
		t.Errorf("Expected exactly 1,200,000 total rows in DB, got %d", totalRows)
	}

	var patchedCount int
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE status = 'Patched'`).Scan(&patchedCount)
	if patchedCount != 200000 {
		t.Errorf("Expected exactly 200,000 auto-patched tickets, got %d", patchedCount)
	}

	var openCount int
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE status = 'Waiting to be Triaged'`).Scan(&openCount)
	if openCount != 1000000 {
		t.Errorf("Expected exactly 1,000,000 open tickets, got %d", openCount)
	}
}
