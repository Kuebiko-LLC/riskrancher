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
	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

type propTestEnv struct {
	h       *ProHandler
	db      *sql.DB
	asRH    func(*http.Request) *http.Request
	asBH    func(*http.Request) *http.Request
	asChief func(*http.Request) *http.Request
	bhFind  int // a BH-origin finding (High)
	plain   int // a non-BH finding
}

func setupProposalsTest(t *testing.T) propTestEnv {
	t.Helper()
	ctx := context.Background()
	db := datastore.InitDB(t.TempDir() + "/prop.db")
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	rh, _ := store.CreateUser(ctx, "rh@ranch.com", "Range Hand", "h", "RangeHand")
	bh, _ := store.CreateUser(ctx, "bh@ranch.com", "Bounty Hunter", "h", "Bounty Hunter")
	chief, _ := store.CreateUser(ctx, "sheriff@ranch.com", "Sheriff", "h", "Sheriff")

	as := func(id int) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, id))
		}
	}

	eng := &proModels.Engagement{Name: "Pentest", Client: "Acme", OwnerEmail: "bh@ranch.com"}
	store.CreateEngagement(ctx, eng)
	bhFinding := &core.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "High", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, bhFinding)
	store.AddFindingsToEngagement(ctx, eng.ID, []int{bhFinding.ID})

	plain := &core.Ticket{Source: "Trivy", AssetIdentifier: "host", Title: "old TLS", Severity: "Medium", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, plain)

	return propTestEnv{NewProHandler(store), db, as(rh.ID), as(bh.ID), as(chief.ID), bhFinding.ID, plain.ID}
}

func propose(e propTestEnv, who func(*http.Request) *http.Request, ticketID int, to, why string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"to_severity": to, "justification": why})
	req := who(httptest.NewRequest(http.MethodPost, "/api/findings/"+strconv.Itoa(ticketID)+"/severity-proposal", bytes.NewReader(body)))
	req.SetPathValue("id", strconv.Itoa(ticketID))
	rr := httptest.NewRecorder()
	e.h.HandleProposeSeverity(rr, req)
	return rr
}

func TestProposeSeverityHandler(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()

	t.Run("RangeHand proposes on a BH finding -> 201, severity unchanged", func(t *testing.T) {
		rr := propose(e, e.asRH, e.bhFind, "Low", "dev dependency")
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		got, _ := e.h.ProStore.GetTicketByID(context.Background(), e.bhFind)
		if got.Severity != "High" {
			t.Errorf("proposal must not change severity yet, got %q", got.Severity)
		}
	})

	t.Run("proposing on a non-BH finding is rejected", func(t *testing.T) {
		rr := propose(e, e.asRH, e.plain, "Low", "x")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for a non-BH finding, got %d", rr.Code)
		}
	})
}

func TestProposalAcceptAndContestFlow(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()
	ctx := context.Background()

	// RH proposes, BH accepts -> applied.
	propose(e, e.asRH, e.bhFind, "Low", "fp")
	mine := proposalIDForTicket(t, e, e.bhFind)

	acc := e.asBH(httptest.NewRequest(http.MethodPost, "/x", nil))
	acc.SetPathValue("id", strconv.Itoa(mine))
	accRR := httptest.NewRecorder()
	e.h.HandleAcceptSeverityProposal(accRR, acc)
	if accRR.Code != http.StatusOK {
		t.Fatalf("accept expected 200, got %d: %s", accRR.Code, accRR.Body.String())
	}
	if got, _ := e.h.ProStore.GetTicketByID(ctx, e.bhFind); got.Severity != "Low" {
		t.Errorf("accept should apply severity, got %q", got.Severity)
	}
}

func TestProposalContestEscalatesToSheriff(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()
	ctx := context.Background()

	propose(e, e.asRH, e.bhFind, "Low", "fp")
	pid := proposalIDForTicket(t, e, e.bhFind)

	// BH contests
	body, _ := json.Marshal(map[string]string{"note": "exploitable in prod"})
	con := e.asBH(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	con.SetPathValue("id", strconv.Itoa(pid))
	conRR := httptest.NewRecorder()
	e.h.HandleContestSeverityProposal(conRR, con)
	if conRR.Code != http.StatusOK {
		t.Fatalf("contest expected 200, got %d", conRR.Code)
	}

	// Sheriff sees it in the queue
	qReq := e.asChief(httptest.NewRequest(http.MethodGet, "/api/severity-proposals/contested", nil))
	qRR := httptest.NewRecorder()
	e.h.HandleContestedProposals(qRR, qReq)
	var q struct {
		Total int `json:"total"`
	}
	json.Unmarshal(qRR.Body.Bytes(), &q)
	if q.Total != 1 {
		t.Errorf("expected 1 contested proposal in the Sheriff queue, got %d", q.Total)
	}

	// Sheriff adjudicates
	adjBody, _ := json.Marshal(map[string]string{"final_severity": "Medium", "note": "mitigated"})
	adj := e.asChief(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(adjBody)))
	adj.SetPathValue("id", strconv.Itoa(pid))
	adjRR := httptest.NewRecorder()
	e.h.HandleAdjudicateSeverityProposal(adjRR, adj)
	if adjRR.Code != http.StatusOK {
		t.Fatalf("adjudicate expected 200, got %d: %s", adjRR.Code, adjRR.Body.String())
	}
	if got, _ := e.h.ProStore.GetTicketByID(ctx, e.bhFind); got.Severity != "Medium" {
		t.Errorf("adjudication should apply final severity, got %q", got.Severity)
	}
}

func TestBountyHunterAlertFeed(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()

	propose(e, e.asRH, e.bhFind, "Low", "fp")

	req := e.asBH(httptest.NewRequest(http.MethodGet, "/api/severity-proposals/mine", nil))
	rr := httptest.NewRecorder()
	e.h.HandleMyPendingProposals(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Total int `json:"total"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Total != 1 {
		t.Errorf("expected the BH to have 1 pending proposal, got %d", resp.Total)
	}
}

func proposalIDForTicket(t *testing.T, e propTestEnv, ticketID int) int {
	t.Helper()
	hist, err := e.h.ProStore.ListProposalsForTicket(context.Background(), ticketID)
	if err != nil || len(hist) == 0 {
		t.Fatalf("no proposal found for ticket %d: %v", ticketID, err)
	}
	return hist[len(hist)-1].ID
}
