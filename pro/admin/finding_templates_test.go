package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func TestFindingTemplateHandlers(t *testing.T) {
	e := setupAuthz(t) // engID owned by owner@ranch.com
	defer e.db.Close()

	// create a template (as the owner BH)
	var tplID int
	t.Run("create + list + get", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"name": "Missing headers", "title": "Missing security headers",
			"severity": "Low", "description": "No X/Y headers.", "remediation": "Add them.", "tags": "web",
		})
		req := e.asOwner(httptest.NewRequest(http.MethodPost, "/api/finding-templates", bytes.NewReader(body)))
		rr := httptest.NewRecorder()
		e.h.HandleCreateTemplate(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var tpl domain.FindingTemplate
		json.Unmarshal(rr.Body.Bytes(), &tpl)
		if tpl.ID == 0 || tpl.CreatedBy != "owner@ranch.com" {
			t.Fatalf("unexpected template: %+v", tpl)
		}
		tplID = tpl.ID

		lr := e.asOwner(httptest.NewRequest(http.MethodGet, "/api/finding-templates", nil))
		lrr := httptest.NewRecorder()
		e.h.HandleListTemplates(lrr, lr)
		var resp struct {
			Total int `json:"total"`
		}
		json.Unmarshal(lrr.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("expected 1 template listed, got %d", resp.Total)
		}
	})

	apply := func(who func(*http.Request) *http.Request, asset string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"template_id": tplID, "asset": asset})
		req := who(httptest.NewRequest(http.MethodPost, "/api/engagements/"+strconv.Itoa(e.engID)+"/apply-template", bytes.NewReader(body)))
		req.SetPathValue("id", strconv.Itoa(e.engID))
		rr := httptest.NewRecorder()
		e.h.HandleApplyTemplate(rr, req)
		return rr
	}

	t.Run("owner applies the template to their engagement", func(t *testing.T) {
		rr := apply(e.asOwner, "web-app-01")
		if rr.Code != http.StatusCreated {
			t.Fatalf("apply expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		findings, _ := e.h.ProStore.ListEngagementFindings(context.Background(), e.engID)
		found := false
		for _, f := range findings {
			if f.Title == "Missing security headers" && f.AssetIdentifier == "web-app-01" {
				found = true
			}
		}
		if !found {
			t.Errorf("template-applied finding not present on the engagement: %+v", findings)
		}
	})

	t.Run("a non-owner cannot apply to the engagement", func(t *testing.T) {
		if rr := apply(e.asOther, "web-app-02"); rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for non-owner apply, got %d", rr.Code)
		}
	})

	t.Run("delete", func(t *testing.T) {
		req := e.asOwner(httptest.NewRequest(http.MethodDelete, "/x", nil))
		req.SetPathValue("id", strconv.Itoa(tplID))
		rr := httptest.NewRecorder()
		e.h.HandleDeleteTemplate(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("delete expected 200, got %d", rr.Code)
		}
	})
}
