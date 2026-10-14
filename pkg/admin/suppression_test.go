package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func itoa(i int) string { return strconv.Itoa(i) }

// ctxWithUser resolves the VIP cookie into the user context the handlers read.
func ctxWithUser(t *testing.T, h *Handler, r *http.Request) context.Context {
	t.Helper()
	c, err := r.Cookie("session_token")
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.Store.GetSession(r.Context(), c.Value)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithValue(r.Context(), auth.UserIDKey, s.UserID)
}

// Logging a false positive through the API keeps that finding closed on the next scan.
func TestSuppressionRuleStaysClosedOnIngest(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	cookie := GetVIPCookie(h.Store)

	body := `{"source":"Semgrep","asset_identifier":"jenkins-ci","title":"Hardcoded AWS secret","rationale":"documented example key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/suppression", strings.NewReader(body))
	req.AddCookie(cookie)
	req = req.WithContext(ctxWithUser(t, h, req))
	rec := httptest.NewRecorder()
	h.HandleCreateSuppressionRule(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var rule domain.SuppressionRule
	json.Unmarshal(rec.Body.Bytes(), &rule)
	if len(rule.DedupeHash) != 64 || rule.Actor == "unknown" {
		t.Fatalf("rule should carry the computed hash and the actor, got %+v", rule)
	}

	// the next scan brings the same finding on the same asset
	batch := []domain.Ticket{{Source: "Semgrep", AssetIdentifier: "jenkins-ci", Title: "Hardcoded AWS secret", Severity: "Critical", Status: "Waiting to be Triaged"}}
	if err := h.Store.ProcessIngestionBatch(context.Background(), "Semgrep", "jenkins-ci", batch); err != nil {
		t.Fatal(err)
	}
	var status string
	db.QueryRow(`SELECT status FROM tickets WHERE dedupe_hash = ?`, rule.DedupeHash).Scan(&status)
	if status != "False Positive" {
		t.Fatalf("a logged false positive must land closed, got %q", status)
	}

	rec = httptest.NewRecorder()
	h.HandleGetSuppressionRules(rec, httptest.NewRequest(http.MethodGet, "/api/admin/suppression", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "documented example key") {
		t.Fatalf("list should show the rule: %d %s", rec.Code, rec.Body.String())
	}
	del := httptest.NewRequest(http.MethodDelete, "/api/admin/suppression/1", nil)
	del.SetPathValue("id", itoa(rule.ID))
	rec = httptest.NewRecorder()
	h.HandleDeleteSuppressionRule(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
}
