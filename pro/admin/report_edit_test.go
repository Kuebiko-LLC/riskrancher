package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	proModels "github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// A report is a live editable document: after it is generated, the author can
// edit its prose and finding selection, and those edits are saved and shown in
// the re-rendered output.
func TestReportIsEditableAndReRenders(t *testing.T) {
	h, db, ids, as := setupReportsTest(t) // ids = [critical, low]
	defer db.Close()

	// 1. Generate the initial report over both findings.
	genBody, _ := json.Marshal(map[string]any{
		"title":             "Draft",
		"executive_summary": "first pass",
		"ticket_ids":        ids,
	})
	genReq := as(httptest.NewRequest(http.MethodPost, "/api/reports/branded", bytes.NewReader(genBody)))
	genRR := httptest.NewRecorder()
	h.HandleGenerateBrandedReport(genRR, genReq)
	if genRR.Code != http.StatusCreated {
		t.Fatalf("generate expected 201, got %d: %s", genRR.Code, genRR.Body.String())
	}
	var report proModels.PentestReport
	json.Unmarshal(genRR.Body.Bytes(), &report)

	// 2. Edit it: new title, new exec summary, author prose, and drop one finding.
	editBody, _ := json.Marshal(map[string]any{
		"title":             "Acme External Pentest (Final)",
		"executive_summary": "After review, one critical remains.",
		"body":              "## Methodology\n\nWe tested over three days from an unauthenticated position.",
		"ticket_ids":        []int{ids[0]}, // keep only the first finding
	})
	editReq := as(httptest.NewRequest(http.MethodPut, "/api/reports/branded/"+strconv.Itoa(report.ID), bytes.NewReader(editBody)))
	editReq.SetPathValue("id", strconv.Itoa(report.ID))
	editRR := httptest.NewRecorder()
	h.HandleUpdateReport(editRR, editReq)
	if editRR.Code != http.StatusOK {
		t.Fatalf("edit expected 200, got %d: %s", editRR.Code, editRR.Body.String())
	}

	// 3. The edits must be saved AND shown: fetch the markdown and check.
	getReq := as(httptest.NewRequest(http.MethodGet, "/api/reports/branded/"+strconv.Itoa(report.ID)+"?format=md", nil))
	getReq.SetPathValue("id", strconv.Itoa(report.ID))
	getRR := httptest.NewRecorder()
	h.HandleGetPentestReport(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get expected 200, got %d", getRR.Code)
	}
	md := getRR.Body.String()

	for _, want := range []string{
		"# Acme External Pentest (Final)",     // new title shown
		"After review, one critical remains.", // new exec summary shown
		"## Methodology",                      // author prose shown
		"unauthenticated position",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("edited report is missing %q\n---\n%s", want, md)
		}
	}
	if strings.Contains(md, "first pass") {
		t.Errorf("stale executive summary still present after edit")
	}

	// The dropped finding must be gone; the kept one present.
	persisted, _ := h.ProStore.GetPentestReport(getReq.Context(), report.ID)
	if len(persisted.TicketIDs) != 1 || persisted.TicketIDs[0] != ids[0] {
		t.Errorf("finding selection edit not saved: %v", persisted.TicketIDs)
	}
	if persisted.Body == "" {
		t.Errorf("author prose (body) was not saved")
	}
}
