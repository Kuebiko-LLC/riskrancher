package report

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func setupTestReport(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")
	store := datastore.NewSQLiteStore(db)
	return NewHandler(store), db
}

func GetVIPCookie(store domain.Store) *http.Cookie {
	user, err := store.GetUserByEmail(context.Background(), "vip@RiskRancher.com")
	if err != nil {
		user, _ = store.CreateUser(context.Background(), "vip@RiskRancher.com", "Test VIP", "hash", "Sheriff")
	}

	store.CreateSession(context.Background(), "vip_token_999", user.ID, time.Now().Add(1*time.Hour))
	return &http.Cookie{Name: "session_token", Value: "vip_token_999"}
}

func TestUploadAndViewReports(t *testing.T) {
	h, db := setupTestReport(t)
	defer db.Close()

	t.Run("1. Test PDF Upload and View", func(t *testing.T) {
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test_report.pdf")
		part.Write([]byte("%PDF-1.4 Fake PDF Content"))
		writer.Close()

		reqUp := httptest.NewRequest(http.MethodPost, "/api/reports/upload", body)
		reqUp.AddCookie(GetVIPCookie(h.Store))
		reqUp.Header.Set("Content-Type", writer.FormDataContentType())
		rrUp := httptest.NewRecorder()
		h.HandleUploadReport(rrUp, reqUp)

		reqView := httptest.NewRequest(http.MethodGet, "/api/reports/view/test_report.pdf", nil)
		reqView.AddCookie(GetVIPCookie(h.Store))
		reqView.SetPathValue("id", "test_report.pdf")
		rrView := httptest.NewRecorder()
		h.HandleViewReport(rrView, reqView)

		if rrView.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for PDF View, got %d", rrView.Code)
		}
	})

	t.Run("2. Test DOCX to HTML", func(t *testing.T) {
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)
		docWriter, _ := zipWriter.Create("word/document.xml")
		docWriter.Write([]byte(`<w:document><w:body><w:p><w:r><w:t>Cross-Site Scripting</w:t></w:r></w:p></w:body></w:document>`))
		zipWriter.Close()

		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "fake_pentest.docx")
		part.Write(buf.Bytes())
		writer.Close()

		reqUp := httptest.NewRequest(http.MethodPost, "/api/reports/upload", body)
		reqUp.Header.Set("Content-Type", writer.FormDataContentType())
		rrUp := httptest.NewRecorder()
		h.HandleUploadReport(rrUp, reqUp)

		reqView := httptest.NewRequest(http.MethodGet, "/api/reports/view/fake_pentest.docx", nil)
		reqView.SetPathValue("id", "fake_pentest.docx")
		rrView := httptest.NewRecorder()
		h.HandleViewReport(rrView, reqView)

		if !strings.Contains(rrView.Body.String(), "Cross-Site Scripting") {
			t.Errorf("DOCX-to-HTML failed. Body: %s", rrView.Body.String())
		}
	})
}

func TestDraftQueueLifecycle(t *testing.T) {
	h, db := setupTestReport(t)
	defer db.Close()

	reportID := "report-uuid-123.pdf"

	// Save Draft
	draftPayload := []byte(`{"title": "SQLi", "severity": "High", "description": "Page 4"}`)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/drafts/report/"+reportID, bytes.NewBuffer(draftPayload))
	reqPost.SetPathValue("id", reportID)
	rrPost := httptest.NewRecorder()
	h.HandleSaveDraft(rrPost, reqPost)

	if rrPost.Code >= 400 {
		t.Fatalf("Failed to save draft! HTTP Code: %d, Error: %s", rrPost.Code, rrPost.Body.String())
	}

	reqGet := httptest.NewRequest(http.MethodGet, "/api/drafts/report/"+reportID, nil)
	reqGet.SetPathValue("id", reportID)
	rrGet := httptest.NewRecorder()
	h.HandleGetDrafts(rrGet, reqGet)

	var drafts []domain.DraftTicket
	json.NewDecoder(rrGet.Body).Decode(&drafts)
	if len(drafts) != 1 || drafts[0].Title != "SQLi" {
		t.Fatalf("Draft GET mismatch")
	}

	// Delete Draft
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/drafts/1", nil)
	reqDel.SetPathValue("draft_id", "1")
	rrDel := httptest.NewRecorder()
	h.HandleDeleteDraft(rrDel, reqDel)
}
