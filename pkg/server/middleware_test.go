package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersSet(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))

	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing security header %s", k)
		}
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestLimitBodyRejectsOversize(t *testing.T) {
	h := LimitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	body := strings.NewReader(strings.Repeat("a", int(defaultMaxBodyBytes)+1))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/tickets", body))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize JSON body: got %d, want 413", rec.Code)
	}
}

func TestLimitBodyAllowsNormal(t *testing.T) {
	reached := false
	h := LimitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	body := strings.NewReader(strings.Repeat("a", 512))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/tickets", body))
	if !reached || rec.Code != http.StatusOK {
		t.Errorf("normal body should pass: code=%d reached=%v", rec.Code, reached)
	}
}

func TestLimitBodyUploadPathGetsLargerCap(t *testing.T) {
	// A body over the default JSON cap but under the upload cap must reach an upload handler.
	size := int(defaultMaxBodyBytes) + 4096
	reached := false
	h := LimitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	body := strings.NewReader(strings.Repeat("a", size))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/reports/upload", body))
	if !reached || rec.Code != http.StatusOK {
		t.Errorf("upload path should allow %d bytes: code=%d reached=%v", size, rec.Code, reached)
	}
}
