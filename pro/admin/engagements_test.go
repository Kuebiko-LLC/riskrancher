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
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// setupEngagementsTest builds a ProHandler over a real DB with the full schema
// and a Bounty Hunter user, and returns a request decorator that authenticates
// as that user (so handlers resolve the owner from context).
func setupEngagementsTest(t *testing.T) (*ProHandler, *sql.DB, func(*http.Request) *http.Request) {
	t.Helper()
	db := datastore.InitDB(filepath.Join(t.TempDir(), "eng.db"))
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	bh, err := store.CreateUser(context.Background(), "hunter@ranch.com", "Doc Holliday", "hash", "Bounty Hunter")
	if err != nil {
		t.Fatalf("create BH user: %v", err)
	}
	asBH := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, bh.ID))
	}
	return NewProHandler(store), db, asBH
}

func TestEngagementHandlersLifecycle(t *testing.T) {
	h, db, asBH := setupEngagementsTest(t)
	defer db.Close()

	var engID int

	t.Run("a Bounty Hunter creates an engagement and owns it", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "Acme External", "client": "Acme"})
		req := asBH(httptest.NewRequest(http.MethodPost, "/api/engagements", bytes.NewReader(body)))
		rr := httptest.NewRecorder()
		h.HandleCreateEngagement(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var e proModels.Engagement
		json.Unmarshal(rr.Body.Bytes(), &e)
		if e.ID == 0 || e.Number != "ENG-0001" || e.OwnerEmail != "hunter@ranch.com" || e.Status != "Active" {
			t.Fatalf("unexpected engagement: %+v", e)
		}
		engID = e.ID
	})

	t.Run("it appears in the list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/engagements", nil)
		rr := httptest.NewRecorder()
		h.HandleListEngagements(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("expected 1 engagement, got %d", resp.Total)
		}
	})

	t.Run("findings can be added and are returned with the engagement", func(t *testing.T) {
		// seed two findings
		store := h.ProStore
		t1 := &core.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
		t2 := &core.Ticket{Source: "Burp", AssetIdentifier: "api", Title: "IDOR", Severity: "Critical", Status: "Waiting to be Triaged"}
		store.CreateTicket(context.Background(), t1)
		store.CreateTicket(context.Background(), t2)

		body, _ := json.Marshal(map[string][]int{"ticket_ids": {t1.ID, t2.ID}})
		req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+strconv.Itoa(engID)+"/findings", bytes.NewReader(body))
		req.SetPathValue("id", strconv.Itoa(engID))
		rr := httptest.NewRecorder()
		h.HandleAddEngagementFindings(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/engagements/"+strconv.Itoa(engID), nil)
		getReq.SetPathValue("id", strconv.Itoa(engID))
		getRR := httptest.NewRecorder()
		h.HandleGetEngagement(getRR, getReq)
		if getRR.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", getRR.Code)
		}
		var detail struct {
			Engagement proModels.Engagement `json:"engagement"`
			Findings   []core.Ticket        `json:"findings"`
		}
		json.Unmarshal(getRR.Body.Bytes(), &detail)
		if len(detail.Findings) != 2 {
			t.Errorf("expected 2 findings on the engagement, got %d", len(detail.Findings))
		}
	})

	t.Run("releasing it flips the status to Released", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+strconv.Itoa(engID)+"/release", nil)
		req.SetPathValue("id", strconv.Itoa(engID))
		rr := httptest.NewRecorder()
		h.HandleReleaseEngagement(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		got, _ := h.ProStore.GetEngagement(context.Background(), engID)
		if got.Status != "Released" {
			t.Errorf("expected Released, got %q", got.Status)
		}
	})
}
