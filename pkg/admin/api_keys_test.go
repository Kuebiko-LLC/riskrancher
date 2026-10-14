package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Sheriff mints a key, sees it once, lists keys without hashes, and revokes it.
func TestAPIKeyLifecycle(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	cookie := GetVIPCookie(h.Store)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys", strings.NewReader(`{"name":"ci-scanner","permissions":"WriteOnly"}`))
	req.AddCookie(cookie)
	req = req.WithContext(ctxWithUser(t, h, req))
	rec := httptest.NewRecorder()
	h.HandleCreateAPIKey(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	raw, _ := created["key"].(string)
	if len(raw) != 64 {
		t.Fatalf("expected a 64-char raw key once, got %q", raw)
	}

	rec = httptest.NewRecorder()
	h.HandleGetAPIKeys(rec, httptest.NewRequest(http.MethodGet, "/api/admin/apikeys", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), raw) || strings.Contains(rec.Body.String(), "token_hash") {
		t.Fatalf("list must not expose the key or its hash: %d %s", rec.Code, rec.Body.String())
	}
	var keys []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 1 || keys[0]["name"] != "ci-scanner" {
		t.Fatalf("expected the one key listed, got %v", keys)
	}
	id := int(keys[0]["id"].(float64))

	del := httptest.NewRequest(http.MethodDelete, "/api/admin/apikeys/1", nil)
	del.SetPathValue("id", itoa(id))
	rec = httptest.NewRecorder()
	h.HandleRevokeAPIKey(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.HandleGetAPIKeys(rec, httptest.NewRequest(http.MethodGet, "/api/admin/apikeys", nil))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("revoked key should be gone, got %s", rec.Body.String())
	}
}
