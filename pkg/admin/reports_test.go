package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// setupReportsTest builds a ProHandler over a real SQLite DB with the full core
// and Pro schema, seeds a Critical and a Low finding, and returns their IDs plus
// a request decorator that authenticates as the report author.
func setupReportsTest(t *testing.T) (*Handler, *sql.DB, []int, func(*http.Request) *http.Request) {
	t.Helper()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "reports.db"))
	store := datastore.NewSQLiteStore(db)

	ctx := context.Background()
	author, _ := store.CreateUser(ctx, "author@ranch.com", "Author BH", "h", "Bounty Hunter")
	as := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, author.ID))
	}
	crit := &domain.Ticket{Source: "Burp", AssetIdentifier: "web-app", Title: "SQL injection in /login", Severity: "Critical", Status: "Waiting to be Triaged"}
	low := &domain.Ticket{Source: "testssl", AssetIdentifier: "edge-lb", Title: "Weak TLS ciphers", Severity: "Low", Status: "Waiting to be Triaged"}
	if err := store.CreateTicket(ctx, crit); err != nil {
		t.Fatalf("seed crit: %v", err)
	}
	if err := store.CreateTicket(ctx, low); err != nil {
		t.Fatalf("seed low: %v", err)
	}
	return NewHandler(store), db, []int{crit.ID, low.ID}, as
}

func TestGenerateBrandedReportBDD(t *testing.T) {
	h, db, ids, as := setupReportsTest(t)
	defer db.Close()

	var reportID int

	t.Run("Given selected findings, a POST generates and stores a report", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"title":             "Acme External Test",
			"client_name":       "Acme Corp",
			"executive_summary": "One critical issue.",
			"ticket_ids":        ids,
		})
		req := as(httptest.NewRequest(http.MethodPost, "/api/reports/branded", bytes.NewReader(body)))
		rr := httptest.NewRecorder()

		h.HandleGenerateBrandedReport(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var got domain.PentestReport
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got.ID == 0 {
			t.Fatalf("expected a persisted report id")
		}
		reportID = got.ID

		if !strings.Contains(got.Markdown, "SQL injection in /login") || !strings.Contains(got.Markdown, "Weak TLS ciphers") {
			t.Errorf("markdown missing findings:\n%s", got.Markdown)
		}
		if crit, low := strings.Index(got.Markdown, "SQL injection"), strings.Index(got.Markdown, "Weak TLS"); crit > low {
			t.Errorf("expected the Critical finding before the Low one")
		}
	})

	t.Run("When ticket_ids is empty, Then it is a 400", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"title": "x", "ticket_ids": []int{}})
		req := as(httptest.NewRequest(http.MethodPost, "/api/reports/branded", bytes.NewReader(body)))
		rr := httptest.NewRecorder()
		h.HandleGenerateBrandedReport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for empty selection, got %d", rr.Code)
		}
	})

	t.Run("Then the stored report downloads as Markdown", func(t *testing.T) {
		req := as(httptest.NewRequest(http.MethodGet, "/api/reports/branded/"+strconv.Itoa(reportID)+"?format=md", nil))
		req.SetPathValue("id", strconv.Itoa(reportID))
		rr := httptest.NewRecorder()

		h.HandleGetPentestReport(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
			t.Errorf("expected markdown content-type, got %q", ct)
		}
		if !strings.Contains(rr.Body.String(), "# Acme External Test") {
			t.Errorf("markdown download missing title heading")
		}
	})

	t.Run("And it appears in the generated-reports list", func(t *testing.T) {
		req := as(httptest.NewRequest(http.MethodGet, "/api/reports/generated", nil))
		rr := httptest.NewRecorder()
		h.HandleListPentestReports(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp struct {
			Total   int `json:"total"`
			Reports []domain.PentestReport
		}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("expected 1 report listed, got %d", resp.Total)
		}
	})
}
