package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The ingest page says what the report parser does: it shows the report
// beside a draft form; it does not extract findings on its own.
func TestIngestPageDoesNotOverclaimTheParser(t *testing.T) {
	app, cookie := appWithUser(t, "RangeHand")
	req := httptest.NewRequest(http.MethodGet, "/ingest", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest page: %d", rec.Code)
	}
	page := rec.Body.String()
	if strings.Contains(page, "extract the findings") || strings.Contains(page, "or PDF") {
		t.Fatalf("the parser card promises extraction and PDF; the product renders a DOCX beside a draft form")
	}
	if !strings.Contains(page, "DOCX") {
		t.Fatalf("the parser card should say what it takes")
	}
}
