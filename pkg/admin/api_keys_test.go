package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A Sheriff mints a key, sees it once, lists keys without hashes, and revokes it.
func TestAPIKeyLifecycle(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	cookie := GetVIPCookie(h.Store)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys", strings.NewReader(`{"name":"ci-scanner","permissions":"FullAdmin"}`))
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

// A new key with no permissions or expiry defaults to the least-privilege Ingest scope
// and a 90-day lifetime, so a leaked scanner key is neither admin nor eternal (RR-H2).
func TestCreateAPIKeyDefaults(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys", strings.NewReader(`{"name":"scanner"}`))
	req.AddCookie(GetVIPCookie(h.Store))
	req = req.WithContext(ctxWithUser(t, h, req))
	rec := httptest.NewRecorder()
	h.HandleCreateAPIKey(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created["permissions"] != "Ingest" {
		t.Errorf("default permission = %v, want Ingest", created["permissions"])
	}
	if created["expires_at"] == nil || created["expires_at"] == "" {
		t.Error("a default key must carry an expiry")
	}

	keys, _ := h.Store.ListAPIKeys(context.Background())
	if len(keys) != 1 || keys[0].ExpiresAt == nil {
		t.Fatalf("expected one key with an expiry, got %v", keys)
	}
	if d := time.Until(*keys[0].ExpiresAt); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("default expiry = %v, want ~90 days", d)
	}
}

// A bogus permission is rejected.
func TestCreateAPIKeyRejectsBadPermission(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys", strings.NewReader(`{"name":"x","permissions":"Superuser"}`))
	req.AddCookie(GetVIPCookie(h.Store))
	req = req.WithContext(ctxWithUser(t, h, req))
	rec := httptest.NewRecorder()
	h.HandleCreateAPIKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad permission = %d, want 400", rec.Code)
	}
}
