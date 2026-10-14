package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
)

func TestHandleAdminResetPassword(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()

	targetUser, _ := a.Store.CreateUser(context.Background(), "forgetful@ranch.com", "Forgetful Fred", "old_hash", "RangeHand")

	payload := map[string]string{
		"new_password": "BrandNewSecurePassword123!",
	}
	body, _ := json.Marshal(payload)

	targetURL := fmt.Sprintf("/api/admin/users/%d/reset-password", targetUser.ID)
	req := httptest.NewRequest(http.MethodPatch, targetURL, bytes.NewBuffer(body))

	req.SetPathValue("id", fmt.Sprintf("%d", targetUser.ID))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	a.HandleAdminResetPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUpdateUserRole(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()

	_, _ = a.Store.CreateUser(context.Background(), "boss@ranch.com", "The Boss", "hash", "Sheriff")
	targetUser, _ := a.Store.CreateUser(context.Background(), "rookie@ranch.com", "Rookie Ray", "hash", "RangeHand")

	payload := map[string]string{
		"global_role": "Wrangler",
	}
	body, _ := json.Marshal(payload)

	targetURL := fmt.Sprintf("/api/admin/users/%d/role", targetUser.ID)
	req := httptest.NewRequest(http.MethodPatch, targetURL, bytes.NewBuffer(body))

	req.AddCookie(GetVIPCookie(a.Store))
	req.SetPathValue("id", fmt.Sprintf("%d", targetUser.ID))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	a.HandleUpdateUserRole(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCreateUser_SheriffInvite(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()

	payload := map[string]string{
		"email":       "magistrate@ranch.com",
		"full_name":   "Mighty Magistrate",
		"password":    "TempPassword123!",
		"global_role": "Magistrate",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", bytes.NewBuffer(body))

	req.AddCookie(GetVIPCookie(a.Store))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	a.HandleCreateUser(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = 'magistrate@ranch.com'`).Scan(&count)
	if count != 1 {
		t.Errorf("Expected user to be created in the database")
	}
}

func TestHandleGetUsers(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)

	req.AddCookie(GetVIPCookie(a.Store))

	rr := httptest.NewRecorder()
	a.HandleGetUsers(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// The admin page's reset button sends no body. The server then generates
// a password, stores its hash, and returns it once as plain text.
func TestResetPasswordWithoutBodyGeneratesOne(t *testing.T) {
	a, db := setupTestAdmin(t)
	defer db.Close()
	target, _ := a.Store.CreateUser(context.Background(), "locked-out@ranch.com", "Locked Out", "old_hash", "RangeHand")

	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/admin/users/%d/reset-password", target.ID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", target.ID))
	rr := httptest.NewRecorder()
	a.HandleAdminResetPassword(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	generated := strings.TrimSpace(rr.Body.String())
	if len(generated) < 16 || strings.Contains(generated, "{") {
		t.Fatalf("expected a generated password as plain text, got %q", generated)
	}
	u, err := a.Store.GetUserByEmail(context.Background(), "locked-out@ranch.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "old_hash" || !auth.CheckPasswordHash(generated, u.PasswordHash) {
		t.Fatalf("the generated password must be the one stored")
	}
}
