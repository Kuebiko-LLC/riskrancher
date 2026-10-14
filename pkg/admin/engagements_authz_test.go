package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type authzEnv struct {
	h       *Handler
	db      *sql.DB
	asOwner func(*http.Request) *http.Request
	asOther func(*http.Request) *http.Request
	asChief func(*http.Request) *http.Request
	engID   int // owned by owner@ranch.com
	finding int // linked to engID
}

func setupAuthz(t *testing.T) authzEnv {
	t.Helper()
	ctx := context.Background()
	db := datastore.InitDB(t.TempDir() + "/authz.db")
	store := datastore.NewSQLiteStore(db)

	owner, _ := store.CreateUser(ctx, "owner@ranch.com", "Owner BH", "h", "Bounty Hunter")
	other, _ := store.CreateUser(ctx, "other@ranch.com", "Other BH", "h", "Bounty Hunter")
	chief, _ := store.CreateUser(ctx, "sheriff@ranch.com", "Sheriff", "h", "Sheriff")
	as := func(id int) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, id))
		}
	}

	eng := &domain.Engagement{Name: "Owner Pentest", Client: "Acme", OwnerEmail: "owner@ranch.com"}
	store.CreateEngagement(ctx, eng)
	f := &domain.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, f)
	store.AddFindingsToEngagement(ctx, eng.ID, []int{f.ID})

	return authzEnv{NewHandler(store), db, as(owner.ID), as(other.ID), as(chief.ID), eng.ID, f.ID}
}

func getEngagement(e authzEnv, who func(*http.Request) *http.Request) *httptest.ResponseRecorder {
	req := who(httptest.NewRequest(http.MethodGet, "/api/engagements/"+strconv.Itoa(e.engID), nil))
	req.SetPathValue("id", strconv.Itoa(e.engID))
	rr := httptest.NewRecorder()
	e.h.HandleGetEngagement(rr, req)
	return rr
}

func TestEngagementReadIsOwnerScoped(t *testing.T) {
	e := setupAuthz(t)
	defer e.db.Close()

	if rr := getEngagement(e, e.asOwner); rr.Code != http.StatusOK {
		t.Errorf("owner should read their engagement, got %d", rr.Code)
	}
	if rr := getEngagement(e, e.asChief); rr.Code != http.StatusOK {
		t.Errorf("sheriff should read any engagement, got %d", rr.Code)
	}
	if rr := getEngagement(e, e.asOther); rr.Code != http.StatusForbidden {
		t.Errorf("a non-owner must NOT read another BH's engagement (held findings leak); got %d", rr.Code)
	}
}

func TestEngagementListIsScoped(t *testing.T) {
	e := setupAuthz(t)
	defer e.db.Close()

	// A second engagement owned by someone else.
	store := e.h.Store
	store.CreateEngagement(context.Background(), &domain.Engagement{Name: "Other", OwnerEmail: "other@ranch.com"})

	total := func(who func(*http.Request) *http.Request) int {
		req := who(httptest.NewRequest(http.MethodGet, "/api/engagements", nil))
		rr := httptest.NewRecorder()
		e.h.HandleListEngagements(rr, req)
		var resp struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		return resp.Total
	}
	if n := total(e.asOwner); n != 1 {
		t.Errorf("owner should see only their 1 engagement, got %d", n)
	}
	if n := total(e.asChief); n != 2 {
		t.Errorf("sheriff should see all 2 engagements, got %d", n)
	}
}

func TestEngagementMutationsAreOwnerOnly(t *testing.T) {
	e := setupAuthz(t)
	defer e.db.Close()

	// non-owner release -> 403, status unchanged
	relReq := e.asOther(httptest.NewRequest(http.MethodPost, "/x", nil))
	relReq.SetPathValue("id", strconv.Itoa(e.engID))
	relRR := httptest.NewRecorder()
	e.h.HandleReleaseEngagement(relRR, relReq)
	if relRR.Code != http.StatusForbidden {
		t.Errorf("non-owner release should be 403, got %d", relRR.Code)
	}
	if eng, _ := e.h.Store.GetEngagement(context.Background(), e.engID); eng.Status != "Active" {
		t.Errorf("engagement should still be Active, got %q", eng.Status)
	}

	// non-owner add-findings -> 403
	body, _ := json.Marshal(map[string][]int{"ticket_ids": {999}})
	addReq := e.asOther(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	addReq.SetPathValue("id", strconv.Itoa(e.engID))
	addRR := httptest.NewRecorder()
	e.h.HandleAddEngagementFindings(addRR, addReq)
	if addRR.Code != http.StatusForbidden {
		t.Errorf("non-owner add-findings should be 403, got %d", addRR.Code)
	}
}

func TestAddFindingsCannotHijackWorkedFindings(t *testing.T) {
	e := setupAuthz(t)
	defer e.db.Close()
	ctx := context.Background()
	store := e.h.Store

	// A finding already being worked (assigned out, in the queue).
	worked := &domain.Ticket{Source: "Trivy", AssetIdentifier: "host", Title: "worked", Severity: "High", Status: "Assigned Out"}
	store.CreateTicket(ctx, worked)

	body, _ := json.Marshal(map[string][]int{"ticket_ids": {worked.ID}})
	req := e.asOwner(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	req.SetPathValue("id", strconv.Itoa(e.engID))
	rr := httptest.NewRecorder()
	e.h.HandleAddEngagementFindings(rr, req)

	// The worked finding must NOT have been pulled in / hidden.
	findings, _ := store.ListEngagementFindings(ctx, e.engID)
	for _, f := range findings {
		if f.ID == worked.ID {
			t.Errorf("a BH hijacked an already-worked finding into their engagement (would hide it from triage)")
		}
	}
}
