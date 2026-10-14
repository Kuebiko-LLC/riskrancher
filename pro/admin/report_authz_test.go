package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

type reportAuthzEnv struct {
	h         *ProHandler
	db        *sql.DB
	asAuthor  func(*http.Request) *http.Request
	asOther   func(*http.Request) *http.Request
	asChief   func(*http.Request) *http.Request
	releasedF int // a normal, released finding
	heldOther int // a finding held in another BH's engagement
}

func setupReportAuthz(t *testing.T) reportAuthzEnv {
	t.Helper()
	ctx := context.Background()
	db := datastore.InitDB(t.TempDir() + "/rauthz.db")
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	author, _ := store.CreateUser(ctx, "author@ranch.com", "Author BH", "h", "Bounty Hunter")
	other, _ := store.CreateUser(ctx, "other@ranch.com", "Other BH", "h", "Bounty Hunter")
	chief, _ := store.CreateUser(ctx, "sheriff@ranch.com", "Sheriff", "h", "Sheriff")
	as := func(id int) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, id))
		}
	}

	released := &core.Ticket{Source: "Trivy", AssetIdentifier: "host", Title: "RELEASED-FINDING", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, released)

	engB := &core.Engagement{Name: "Other", OwnerEmail: "other@ranch.com"}
	store.CreateEngagement(ctx, engB)
	held := &core.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "HELD-SECRET-FINDING", Severity: "Critical", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, held)
	store.AddFindingsToEngagement(ctx, engB.ID, []int{held.ID})

	return reportAuthzEnv{NewProHandler(store), db, as(author.ID), as(other.ID), as(chief.ID), released.ID, held.ID}
}

// generate a report as `author` over the released finding; returns its id.
func (e reportAuthzEnv) makeReport(t *testing.T) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"title": "Rep", "ticket_ids": []int{e.releasedF}})
	req := e.asAuthor(httptest.NewRequest(http.MethodPost, "/api/reports/branded", bytes.NewReader(body)))
	rr := httptest.NewRecorder()
	e.h.HandleGenerateBrandedReport(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("make report: %d %s", rr.Code, rr.Body.String())
	}
	var rep core.PentestReport
	json.Unmarshal(rr.Body.Bytes(), &rep)
	return rep.ID
}

func TestReportReadEditIsAuthorOrSheriffOnly(t *testing.T) {
	e := setupReportAuthz(t)
	defer e.db.Close()
	id := e.makeReport(t)

	get := func(who func(*http.Request) *http.Request) int {
		req := who(httptest.NewRequest(http.MethodGet, "/api/reports/branded/"+strconv.Itoa(id), nil))
		req.SetPathValue("id", strconv.Itoa(id))
		rr := httptest.NewRecorder()
		e.h.HandleGetPentestReport(rr, req)
		return rr.Code
	}
	if c := get(e.asAuthor); c != http.StatusOK {
		t.Errorf("author should read own report, got %d", c)
	}
	if c := get(e.asChief); c != http.StatusOK {
		t.Errorf("sheriff should read any report, got %d", c)
	}
	if c := get(e.asOther); c != http.StatusForbidden {
		t.Errorf("a non-author must not read the report, got %d", c)
	}

	// Edit by non-author -> 403
	body, _ := json.Marshal(map[string]any{"title": "hax", "ticket_ids": []int{e.releasedF}})
	putReq := e.asOther(httptest.NewRequest(http.MethodPut, "/api/reports/branded/"+strconv.Itoa(id), bytes.NewReader(body)))
	putReq.SetPathValue("id", strconv.Itoa(id))
	putRR := httptest.NewRecorder()
	e.h.HandleUpdateReport(putRR, putReq)
	if putRR.Code != http.StatusForbidden {
		t.Errorf("non-author edit should be 403, got %d", putRR.Code)
	}
}

func TestReportGenerationCannotPullHeldFindings(t *testing.T) {
	e := setupReportAuthz(t)
	defer e.db.Close()

	// Author tries to generate over the released finding AND another BH's held finding.
	body, _ := json.Marshal(map[string]any{"title": "Rep", "ticket_ids": []int{e.releasedF, e.heldOther}})
	req := e.asAuthor(httptest.NewRequest(http.MethodPost, "/api/reports/branded", bytes.NewReader(body)))
	rr := httptest.NewRecorder()
	e.h.HandleGenerateBrandedReport(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var rep core.PentestReport
	json.Unmarshal(rr.Body.Bytes(), &rep)

	if !strings.Contains(rep.Markdown, "RELEASED-FINDING") {
		t.Errorf("released finding should be in the report")
	}
	if strings.Contains(rep.Markdown, "HELD-SECRET-FINDING") {
		t.Errorf("another BH's held finding leaked into the report")
	}
	for _, id := range rep.TicketIDs {
		if id == e.heldOther {
			t.Errorf("held finding id was persisted into the report")
		}
	}
}
