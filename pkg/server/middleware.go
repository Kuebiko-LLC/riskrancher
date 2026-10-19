package server

import (
	"net/http"
	"strings"
)

// Body-size caps. These are fail-closed bootstrap defaults: a finite ceiling so a
// request body can never be unbounded (CWE-770). The JSON API and form posts get the
// small cap; the upload endpoints (pentest reports, evidence images, bulk ingest) get
// a larger one because they legitimately carry files. Tunable later via app config.
const (
	defaultMaxBodyBytes int64 = 1 << 20  // 1 MiB
	uploadMaxBodyBytes  int64 = 32 << 20 // 32 MiB
)

// isUploadPath reports whether a path legitimately carries a large body and so gets
// the upload cap instead of the default one.
func isUploadPath(p string) bool {
	return strings.HasPrefix(p, "/api/reports/upload") ||
		strings.HasPrefix(p, "/api/images/upload") ||
		strings.HasPrefix(p, "/api/ingest")
}

// LimitBody bounds every request body. It rejects an honestly oversized request up
// front with 413 (the Content-Length says it is too big) and wraps the body in a
// MaxBytesReader as the backstop for a chunked or lying Content-Length, so a handler
// that streams the body still cannot be made to read past the cap.
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultMaxBodyBytes
		if isUploadPath(r.URL.Path) {
			limit = uploadMaxBodyBytes
		}
		if r.ContentLength > limit {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders sets the baseline response headers a scanner expects and a browser
// enforces: no MIME sniffing, no framing (clickjacking), a tight referrer, and a CSP.
// The CSP keeps default-src on 'self' and forbids plugins, base-uri games and framing,
// but has to allow 'unsafe-inline' because the UI still uses inline on* handlers and
// style attributes. Moving those to external scripts is the follow-up that lets the
// 'unsafe-inline' come out and makes the CSP a real XSS control rather than a present one.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
