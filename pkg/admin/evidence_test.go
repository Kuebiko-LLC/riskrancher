package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func multipartImage(t *testing.T, field, filename string, data []byte, caption string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile(field, filename)
	fw.Write(data)
	mw.WriteField("caption", caption)
	mw.Close()
	return &body, mw.FormDataContentType()
}

func TestEvidenceUploadAuthzAndServe(t *testing.T) {
	e := setupAuthz(t) // engID owned by owner@ranch.com, finding e.finding linked to it
	defer e.db.Close()

	upload := func(who func(*http.Request) *http.Request, data []byte) *httptest.ResponseRecorder {
		body, ctype := multipartImage(t, "image", "shot.png", data, "login popup")
		req := who(httptest.NewRequest(http.MethodPost, "/api/findings/"+strconv.Itoa(e.finding)+"/evidence", body))
		req.Header.Set("Content-Type", ctype)
		req.SetPathValue("id", strconv.Itoa(e.finding))
		rr := httptest.NewRecorder()
		e.h.HandleUploadEvidence(rr, req)
		return rr
	}

	var evID int
	t.Run("owner uploads a screenshot", func(t *testing.T) {
		rr := upload(e.asOwner, pngBytes(t, 400, 300))
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var ev domain.Evidence
		json.Unmarshal(rr.Body.Bytes(), &ev)
		if ev.ID == 0 || ev.ContentType != "image/png" || ev.Caption != "login popup" {
			t.Fatalf("unexpected evidence: %+v", ev)
		}
		evID = ev.ID
	})

	t.Run("a non-owner cannot upload", func(t *testing.T) {
		if rr := upload(e.asOther, pngBytes(t, 100, 100)); rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("a non-image is rejected", func(t *testing.T) {
		body, ctype := multipartImage(t, "image", "x.txt", []byte("not an image"), "c")
		req := e.asOwner(httptest.NewRequest(http.MethodPost, "/x", body))
		req.Header.Set("Content-Type", ctype)
		req.SetPathValue("id", strconv.Itoa(e.finding))
		rr := httptest.NewRecorder()
		e.h.HandleUploadEvidence(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for a non-image, got %d", rr.Code)
		}
	})

	t.Run("the image serves and decodes", func(t *testing.T) {
		req := e.asOwner(httptest.NewRequest(http.MethodGet, "/api/evidence/"+strconv.Itoa(evID), nil))
		req.SetPathValue("id", strconv.Itoa(evID))
		rr := httptest.NewRecorder()
		e.h.HandleGetEvidenceImage(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "image/png" {
			t.Errorf("expected image/png, got %q", ct)
		}
		if _, _, err := image.Decode(bytes.NewReader(rr.Body.Bytes())); err != nil {
			t.Errorf("served bytes should decode as an image: %v", err)
		}
	})

	t.Run("listed under the finding, then deletable by the owner", func(t *testing.T) {
		req := e.asOwner(httptest.NewRequest(http.MethodGet, "/x", nil))
		req.SetPathValue("id", strconv.Itoa(e.finding))
		rr := httptest.NewRecorder()
		e.h.HandleListEvidence(rr, req)
		var resp struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("expected 1 evidence, got %d", resp.Total)
		}

		del := e.asOwner(httptest.NewRequest(http.MethodDelete, "/x", nil))
		del.SetPathValue("id", strconv.Itoa(evID))
		delRR := httptest.NewRecorder()
		e.h.HandleDeleteEvidence(delRR, del)
		if delRR.Code != http.StatusOK {
			t.Errorf("owner delete should be 200, got %d", delRR.Code)
		}
		if list, _ := e.h.Store.ListEvidenceForTicket(context.Background(), e.finding); len(list) != 0 {
			t.Errorf("evidence should be gone after delete")
		}
	})
}
