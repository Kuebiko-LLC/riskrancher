package ingest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func setupTestIngest(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")
	store := datastore.NewSQLiteStore(db)
	return NewHandler(store), db
}

func GetVIPCookie(store domain.Store) *http.Cookie {

	user, err := store.GetUserByEmail(context.Background(), "vip@RiskRancher.com")
	if err != nil {
		user, _ = store.CreateUser(context.Background(), "vip@RiskRancher.com", "Test VIP", "hash", "Sheriff")
	}

	store.CreateSession(context.Background(), "vip_token_999", user.ID, time.Now().Add(1*time.Hour))
	return &http.Cookie{Name: "session_token", Value: "vip_token_999"}
}

func TestAutoPatchMissingFindings(t *testing.T) {
	app, db := setupTestIngest(t)
	defer db.Close()

	payload1 := []byte(`[
			{"title": "Vuln A", "severity": "High"},
			{"title": "Vuln B", "severity": "Medium"}
		]
	`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(payload1))
	req1.AddCookie(GetVIPCookie(app.Store))
	rr1 := httptest.NewRecorder()
	app.HandleIngest(rr1, req1)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM tickets WHERE status = 'Waiting to be Triaged'").Scan(&count)
	if count != 2 {
		t.Fatalf("Expected 2 unpatched tickets, got %d", count)
	}

	payload2 := []byte(` [
			{"title": "Vuln A", "severity": "High"}
		]`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(payload2))
	req2.AddCookie(GetVIPCookie(app.Store))
	rr2 := httptest.NewRecorder()
	app.HandleIngest(rr2, req2)

	var statusB string
	var patchedAt sql.NullTime

	err := db.QueryRow("SELECT status, patched_at FROM tickets WHERE title = 'Vuln B'").Scan(&statusB, &patchedAt)
	if err != nil {
		t.Fatalf("Failed to query Vuln B: %v", err)
	}

	if statusB != "Patched" {
		t.Errorf("Expected Vuln B status to be 'Patched', got '%s'", statusB)
	}

	if !patchedAt.Valid {
		t.Errorf("Expected Vuln B to have a patched_at timestamp, but it was NULL")
	}
}

func TestHandleIngest(t *testing.T) {
	a, db := setupTestIngest(t)
	defer db.Close()

	sendIngestRequest := func(findings []domain.Ticket) *httptest.ResponseRecorder {
		body, _ := json.Marshal(findings)
		req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		a.HandleIngest(rr, req)
		return rr
	}

	t.Run("1. Fresh Ingestion", func(t *testing.T) {
		findings := []domain.Ticket{
			{
				Source:          "CrowdStrike",
				AssetIdentifier: "Server-01",
				Title:           "Malware Detected",
				Severity:        "Critical",
			},
		}

		rr := sendIngestRequest(findings)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", rr.Code)
		}

		var count int
		db.QueryRow("SELECT COUNT(*) FROM tickets").Scan(&count)
		if count != 1 {
			t.Errorf("expected 1 ticket in DB, got %d", count)
		}
	})

	t.Run("2. Deduplication", func(t *testing.T) {
		time.Sleep(1 * time.Second)

		findings := []domain.Ticket{
			{
				Source:          "CrowdStrike",
				AssetIdentifier: "Server-01",
				Title:           "Malware Detected",
				Severity:        "Critical",
				Description:     "Updated Description",
			},
		}

		rr := sendIngestRequest(findings)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", rr.Code)
		}

		var count int
		db.QueryRow("SELECT COUNT(*) FROM tickets").Scan(&count)
		if count != 1 {
			t.Errorf("expected still 1 ticket in DB due to dedupe, got %d", count)
		}

		var desc string
		db.QueryRow("SELECT description FROM tickets WHERE title = 'Malware Detected'").Scan(&desc)
		if desc != "Updated Description" {
			t.Errorf("expected description to update to 'Updated Description', got '%s'", desc)
		}
	})

	t.Run("3. Scoped Auto-Patching", func(t *testing.T) {
		findings := []domain.Ticket{
			{
				Source:          "CrowdStrike",
				AssetIdentifier: "Server-01",
				Title:           "Outdated Antivirus",
				Severity:        "High",
			},
		}

		rr := sendIngestRequest(findings)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", rr.Code)
		}

		var totalCount int
		db.QueryRow("SELECT COUNT(*) FROM tickets").Scan(&totalCount)
		if totalCount != 2 {
			t.Errorf("expected 2 total tickets in DB, got %d", totalCount)
		}

		var status string
		db.QueryRow("SELECT status FROM tickets WHERE title = 'Malware Detected'").Scan(&status)
		if status != "Patched" {
			t.Errorf("expected missing vulnerability to be auto-patched, but status is '%s'", status)
		}
	})
}

func TestCSVIngestion(t *testing.T) {
	app, db := setupTestIngest(t)
	defer db.Close()

	_, err := db.Exec(`
		INSERT INTO data_adapters (
			id, name, source_name, findings_path,
			mapping_title, mapping_asset, mapping_severity, mapping_description, mapping_remediation
		) VALUES (
			999, 'Legacy Scanner V1', 'LegacyScan', '.',
			'Vuln_Name', 'Server_IP', 'Risk_Level', 'Details', 'Fix_Steps'
		)
	`)
	if err != nil {
		t.Fatalf("Failed to setup test adapter: %v", err)
	}

	rawCSV := `Vuln_Name,Server_IP,Risk_Level,Details,Junk_Column
SQL Injection,192.168.1.50,Critical,Found in login form,ignore_this
Outdated Apache,192.168.1.50,High,Upgrade to 2.4.50,ignore_this`

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "scan_results.csv")
	part.Write([]byte(rawCSV))

	writer.WriteField("adapter_id", "999")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/ingest/csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	app.HandleCSVIngest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM tickets WHERE source = 'LegacyScan'").Scan(&count)

	if count != 2 {
		t.Errorf("Expected 2 tickets ingested from CSV, got %d", count)
	}

	var title, severity string
	db.QueryRow("SELECT title, severity FROM tickets WHERE title = 'SQL Injection'").Scan(&title, &severity)
	if severity != "Critical" {
		t.Errorf("CSV Mapping failed! Expected severity 'Critical', got '%s'", severity)
	}
}

func TestAutoPatchEdgeCases(t *testing.T) {
	h, db := setupTestIngest(t) // Swapped 'app' for 'h'
	defer db.Close()

	db.Exec(`
       INSERT INTO tickets (source, title, severity, dedupe_hash, status) 
       VALUES ('App B', 'App B Vuln', 'High', 'hash-app-b', 'Waiting to be Triaged')
    `)

	payload1 := []byte(`[
          {"source": "App A", "title": "Vuln 1", "severity": "High"},
          {"source": "App A", "title": "Vuln 2", "severity": "Medium"}
       ]`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(payload1))
	req1.AddCookie(GetVIPCookie(h.Store))
	req1.Header.Set("Content-Type", "application/json")

	rr1 := httptest.NewRecorder()
	h.HandleIngest(rr1, req1)

	payload2 := []byte(`[
          {"source": "App A", "title": "Vuln 1", "severity": "High"}
       ]`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(payload2))
	req2.AddCookie(GetVIPCookie(h.Store))
	req2.Header.Set("Content-Type", "application/json")

	rr2 := httptest.NewRecorder()
	h.HandleIngest(rr2, req2)

	var status2 string
	db.QueryRow("SELECT status FROM tickets WHERE title = 'Vuln 2'").Scan(&status2)
	if status2 != "Patched" {
		t.Errorf("Expected Vuln 2 to be 'Patched', got '%s'", status2)
	}

	var statusB string
	db.QueryRow("SELECT status FROM tickets WHERE title = 'App B Vuln'").Scan(&statusB)
	if statusB != "Waiting to be Triaged" {
		t.Errorf("CRITICAL FAILURE: Blast radius exceeded! App B status changed to '%s'", statusB)
	}
}

func TestHandleIngest_MultiAssetDiffing(t *testing.T) {
	// THE GO 1.26 GC TWEAK: Force Go to keep RAM usage under 2GB
	// This makes the GC run aggressively, trading a tiny bit of CPU for massive RAM savings.
	previousLimit := debug.SetMemoryLimit(2 * 1024 * 1024 * 1024)
	defer debug.SetMemoryLimit(previousLimit)

	a, db := setupTestIngest(t)
	db.Exec(`PRAGMA synchronous = OFF;`)
	defer db.Close()

	_, err := db.Exec(`INSERT INTO tickets (source, asset_identifier, title, status, severity, dedupe_hash) VALUES 
		('Trivy', 'Server-A', 'Old Vuln A', 'Waiting to be Triaged', 'High', 'hash_A_1'),
		('Trivy', 'Server-B', 'Old Vuln B', 'Waiting to be Triaged', 'Critical', 'hash_B_1')`)
	if err != nil {
		t.Fatalf("Failed to seed database: %v", err)
	}

	incomingPayload := []domain.Ticket{
		{
			Source:          "Trivy",
			AssetIdentifier: "Server-A",
			Title:           "New Vuln A",
			Severity:        "High",
			DedupeHash:      "hash_A_2",
		},
	}

	body, _ := json.Marshal(incomingPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	a.HandleIngest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", rr.Code)
	}

	var statusA string
	db.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = 'hash_A_1'`).Scan(&statusA)
	if statusA != "Patched" {
		t.Errorf("Expected Server-A's old ticket to be Auto-Patched, got '%s'", statusA)
	}

	var statusB string
	db.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = 'hash_B_1'`).Scan(&statusB)
	if statusB != "Waiting to be Triaged" {
		t.Errorf("CRITICAL BUG: Server-B's ticket was altered! Expected 'Waiting to be Triaged', got '%s'", statusB)
	}
}

func TestHandleIngest_OneMillionTicketStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping 1-million ticket stress test in short mode")
	}

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

func TestSyncLogReceipts(t *testing.T) {
	h, db := setupTestIngest(t)
	defer db.Close()
	db.Exec(`CREATE TABLE IF NOT EXISTS sync_logs (id INTEGER PRIMARY KEY, source TEXT, status TEXT, records_processed INTEGER, error_message TEXT)`)

	payload := []byte(`[{"source": "Dependabot", "asset_identifier": "repo-1", "title": "Vuln 1", "severity": "High"}]`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(payload))
	req1.AddCookie(GetVIPCookie(h.Store))
	req1.Header.Set("Content-Type", "application/json")
	h.HandleIngest(httptest.NewRecorder(), req1)

	badPayload := []byte(`[{"source": "Dependabot", "title": "Vuln 1", "severity": "High", "status": "GarbageStatus"}]`)

	req2 := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewBuffer(badPayload))
	req2.AddCookie(GetVIPCookie(h.Store))
	req2.Header.Set("Content-Type", "application/json")
	h.HandleIngest(httptest.NewRecorder(), req2)

	var successCount, failCount, processed int
	db.QueryRow("SELECT COUNT(*), MAX(records_processed) FROM sync_logs WHERE source = 'Dependabot' AND status = 'Success'").Scan(&successCount, &processed)
	db.QueryRow("SELECT COUNT(*) FROM sync_logs WHERE status = 'Failed'").Scan(&failCount)

	if successCount != 1 || processed != 1 {
		t.Errorf("System failed to log successful sync receipt. Got count: %d, processed: %d", successCount, processed)
	}
	if failCount != 1 {
		t.Errorf("System failed to log failed sync receipt. Got count: %d", failCount)
	}
}

func TestUIFileDropIngestion(t *testing.T) {
	h, db := setupTestIngest(t)
	defer db.Close()

	res, err := db.Exec(`INSERT INTO data_adapters (name, source_name, mapping_title, mapping_asset, mapping_severity) VALUES ('UI-Tool', 'UITool', 'Name', 'Host', 'Risk')`)
	if err != nil {
		t.Fatalf("failed to seed adapter: %v", err)
	}
	adapterID, _ := res.LastInsertId()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test_findings.csv")
	part.Write([]byte("Name,Host,Risk\nUnauthorized Access,10.0.0.1,Critical"))

	_ = writer.WriteField("adapter_id", fmt.Sprintf("%d", adapterID))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/ingest/csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(GetVIPCookie(h.Store))
	rr := httptest.NewRecorder()
	h.HandleCSVIngest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM tickets WHERE source = 'UITool'").Scan(&count)
	if count != 1 {
		t.Errorf("UI Drop failed: expected 1 ticket, got %d", count)
	}
}
