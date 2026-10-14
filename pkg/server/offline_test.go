package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The binary makes no outbound network calls. Nothing in the product
// packages builds an HTTP client or dials out. cmd/stresstest is a load
// tool that talks to a running server on loopback, so it is left out.
func TestNoOutboundHTTP(t *testing.T) {
	var offenders []string
	for _, root := range []string{"../../pkg", "../../cmd"} {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "cmd/stresstest") {
				return nil
			}
			src, _ := os.ReadFile(path)
			for _, needle := range []string{"http.Get(", "http.Post(", "http.Client{", "http.DefaultClient", "net.Dial"} {
				if strings.Contains(string(src), needle) {
					offenders = append(offenders, path+": "+needle)
				}
			}
			return nil
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("the product must not reach out:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// The shutdown route asks the server to stop, and the server stops.
func TestShutdownStopsTheServer(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	done := make(chan struct{})
	app.Shutdown = func() { close(done) }
	req := httptest.NewRequest(http.MethodPost, "/api/admin/shutdown", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("shutdown: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("the server was never asked to stop")
	}
}
