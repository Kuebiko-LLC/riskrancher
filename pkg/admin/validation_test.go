package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestProposeRejectsInvalidSeverity(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()

	if rr := propose(e, e.asRH, e.bhFind, "Banana", "x"); rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a bogus severity, got %d", rr.Code)
	}
	// nothing should have been recorded
	hist, _ := e.h.Store.ListProposalsForTicket(context.Background(), e.bhFind)
	if len(hist) != 0 {
		t.Errorf("a rejected proposal must not be stored, got %d", len(hist))
	}
	// sanity: a valid severity still works
	if rr := propose(e, e.asRH, e.bhFind, "Low", "ok"); rr.Code != http.StatusCreated {
		t.Errorf("valid severity should be 201, got %d", rr.Code)
	}
}

func TestAdjudicateRejectsInvalidSeverity(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()

	propose(e, e.asRH, e.bhFind, "Low", "x")
	pid := proposalIDForTicket(t, e, e.bhFind)

	body, _ := json.Marshal(map[string]string{"final_severity": "Nope", "note": "n"})
	req := e.asChief(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	req.SetPathValue("id", strconv.Itoa(pid))
	rr := httptest.NewRecorder()
	e.h.HandleAdjudicateSeverityProposal(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a bogus final_severity, got %d", rr.Code)
	}
}

func TestAddFindingsRejectsHugeArray(t *testing.T) {
	e := setupAuthz(t)
	defer e.db.Close()

	ids := make([]int, 2001)
	for i := range ids {
		ids[i] = i + 1
	}
	body, _ := json.Marshal(map[string][]int{"ticket_ids": ids})
	req := e.asOwner(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	req.SetPathValue("id", strconv.Itoa(e.engID))
	rr := httptest.NewRecorder()
	e.h.HandleAddEngagementFindings(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an oversized ticket_ids array, got %d", rr.Code)
	}
}

func TestServerErrorsAreGeneric(t *testing.T) {
	e := setupProposalsTest(t)
	defer e.db.Close()

	// Propose on a ticket that does not exist -> internal error, generic body.
	body, _ := json.Marshal(map[string]string{"to_severity": "Low", "justification": "x"})
	req := e.asRH(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	req.SetPathValue("id", "999999")
	rr := httptest.NewRecorder()
	e.h.HandleProposeSeverity(rr, req)

	if rr.Code < 400 {
		t.Fatalf("expected an error status, got %d", rr.Code)
	}
	lower := strings.ToLower(rr.Body.String())
	if strings.Contains(lower, "sql") || strings.Contains(lower, "db error") {
		t.Errorf("error body leaks internal detail: %q", rr.Body.String())
	}
}
