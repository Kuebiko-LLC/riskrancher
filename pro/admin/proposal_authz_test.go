package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	datastore "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	core "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestProposalAcceptIsOwnerOnlyAndStateChecked(t *testing.T) {
	ctx := context.Background()
	db := datastore.InitDB(t.TempDir() + "/pauthz.db")
	defer db.Close()
	store := datastore.NewSQLiteStore(db)
	h := NewProHandler(store)

	owner, _ := store.CreateUser(ctx, "owner@ranch.com", "Owner BH", "h", "Bounty Hunter")
	other, _ := store.CreateUser(ctx, "other@ranch.com", "Other BH", "h", "Bounty Hunter")
	as := func(id int) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), auth.UserIDKey, id))
		}
	}

	eng := &core.Engagement{Name: "P", OwnerEmail: "owner@ranch.com"}
	store.CreateEngagement(ctx, eng)
	f := &core.Ticket{Source: "Burp", AssetIdentifier: "web", Title: "XSS", Severity: "Critical", Status: "Waiting to be Triaged"}
	store.CreateTicket(ctx, f)
	store.AddFindingsToEngagement(ctx, eng.ID, []int{f.ID})
	p, _ := store.ProposeSeverityChange(ctx, f.ID, "Low", "fp", "rh@ranch.com")

	accept := func(who func(*http.Request) *http.Request) *httptest.ResponseRecorder {
		req := who(httptest.NewRequest(http.MethodPost, "/x", nil))
		req.SetPathValue("id", strconv.Itoa(p.ID))
		rr := httptest.NewRecorder()
		h.HandleAcceptSeverityProposal(rr, req)
		return rr
	}

	t.Run("a non-owner Bounty Hunter cannot accept", func(t *testing.T) {
		if rr := accept(as(other.ID)); rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for non-owner accept, got %d", rr.Code)
		}
		if got, _ := store.GetTicketByID(ctx, f.ID); got.Severity != "Critical" {
			t.Errorf("severity must be unchanged after a blocked accept, got %q", got.Severity)
		}
	})

	t.Run("the owner can accept", func(t *testing.T) {
		if rr := accept(as(owner.ID)); rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for owner accept, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("accepting an already-resolved proposal is a 409", func(t *testing.T) {
		if rr := accept(as(owner.ID)); rr.Code != http.StatusConflict {
			t.Errorf("expected 409 re-accepting, got %d", rr.Code)
		}
	})

	t.Run("contesting a resolved proposal is a 409", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"note": "n"})
		req := as(owner.ID)(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
		req.SetPathValue("id", strconv.Itoa(p.ID))
		rr := httptest.NewRecorder()
		h.HandleContestSeverityProposal(rr, req)
		if rr.Code != http.StatusConflict {
			t.Errorf("expected 409 contesting resolved, got %d", rr.Code)
		}
	})
}
