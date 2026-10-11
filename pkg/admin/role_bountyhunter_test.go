package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The Bounty Hunter (pentester) persona must be an assignable role.
func TestUpdateUserRoleAcceptsBountyHunter(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()

	user, _ := a.Store.CreateUser(context.Background(), "hunter@ranch.com", "Doc Holliday", "hash", "RangeHand")

	patch := func(role string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"global_role": role})
		req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/admin/users/%d/role", user.ID), bytes.NewBuffer(body))
		req.SetPathValue("id", fmt.Sprintf("%d", user.ID))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		a.HandleUpdateUserRole(rr, req)
		return rr
	}

	t.Run("Bounty Hunter is accepted", func(t *testing.T) {
		if rr := patch("Bounty Hunter"); rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for Bounty Hunter, got %d: %s", rr.Code, rr.Body.String())
		}
		got, _ := a.Store.GetUserByID(context.Background(), user.ID)
		if got.GlobalRole != "Bounty Hunter" {
			t.Errorf("expected role persisted as Bounty Hunter, got %q", got.GlobalRole)
		}
	})

	t.Run("a bogus role is still rejected", func(t *testing.T) {
		if rr := patch("Space Cowboy"); rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for an invalid role, got %d", rr.Code)
		}
	})
}
