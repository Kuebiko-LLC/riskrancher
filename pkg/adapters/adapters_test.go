package adapters

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func setupTestAdapters(t *testing.T) (*Handler, *sql.DB) {
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

func TestHandleAdapterIngest(t *testing.T) {
	h, db := setupTestAdapters(t)
	defer db.Close()

	adapterPayload := []byte(`{"name": "Trivy Test", "source_name": "TrivyScanner", "findings_path": "Results", "mapping_title": "VulnerabilityID", "mapping_asset": "Target", "mapping_severity": "Severity"}`)
	reqAdapter := httptest.NewRequest(http.MethodPost, "/api/adapters", bytes.NewBuffer(adapterPayload))
	reqAdapter.AddCookie(GetVIPCookie(h.Store))
	reqAdapter.Header.Set("Content-Type", "application/json")
	rrAdapter := httptest.NewRecorder()

	h.HandleCreateAdapter(rrAdapter, reqAdapter)

	payload := []byte(`{"SchemaVersion": 2, "Results": [{"VulnerabilityID": "CVE-1", "Target": "A", "Severity": "HIGH"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ingest/Trivy%20Test", bytes.NewBuffer(payload))
	req.AddCookie(GetVIPCookie(h.Store))
	req.Header.Set("Content-Type", "application/json")

	req.SetPathValue("name", "Trivy Test")
	rr := httptest.NewRecorder()
	h.HandleAdapterIngest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", rr.Code)
	}
}

func TestGetAdapters(t *testing.T) {
	h, db := setupTestAdapters(t)
	defer db.Close()

	db.Exec(`INSERT INTO data_adapters (name, source_name, findings_path, mapping_title, mapping_asset, mapping_severity) VALUES ('Trivy Test', 'Trivy', 'Results', 'VulnerabilityID', 'PkgName', 'Severity')`)

	req := httptest.NewRequest(http.MethodGet, "/api/adapters", nil)
	req.AddCookie(GetVIPCookie(h.Store))
	rr := httptest.NewRecorder()
	h.HandleGetAdapters(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}
}

func TestCreateAdapter(t *testing.T) {
	h, db := setupTestAdapters(t)
	defer db.Close()

	payload := []byte(`{"name": "AcmeSec", "source_name": "Acme", "findings_path": "issues", "mapping_title": "t", "mapping_asset": "a", "mapping_severity": "s"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/adapters", bytes.NewBuffer(payload))
	req.AddCookie(GetVIPCookie(h.Store))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCreateAdapter(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", rr.Code)
	}
}

func TestJSONIngestion(t *testing.T) {
	h, db := setupTestAdapters(t)
	defer db.Close()

	_, err := db.Exec(`
       INSERT INTO data_adapters (
          id, name, source_name, findings_path,
          mapping_title, mapping_asset, mapping_severity
       ) VALUES (
          998, 'NestedScanner', 'DeepScan', 'scan_data.results',
          'vuln_name', 'target_ip', 'risk_level'
       )
    `)
	if err != nil {
		t.Fatalf("Failed to setup nested adapter: %v", err)
	}

	payload := []byte(`{
       "metadata": { "version": "1.0" },
       "scan_data": {
          "results": [
             {
                "vuln_name": "Log4j RCE",
                "target_ip": "10.0.0.5",
                "risk_level": "Critical"
             }
          ]
       }
    }`)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest/NestedScanner", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(GetVIPCookie(h.Store))

	req.SetPathValue("name", "NestedScanner")
	rr := httptest.NewRecorder()
	h.HandleAdapterIngest(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var title, severity string
	err = db.QueryRow("SELECT title, severity FROM tickets WHERE source = 'DeepScan'").Scan(&title, &severity)
	if err != nil {
		t.Fatalf("Failed to query ingested ticket: %v", err)
	}

	if title != "Log4j RCE" || severity != "Critical" {
		t.Errorf("JSON Mapping failed! Expected 'Log4j RCE' / 'Critical', got '%s' / '%s'", title, severity)
	}
}
