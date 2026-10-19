package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThrottleAllowsThenBlocks(t *testing.T) {
	th := NewThrottle(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !th.allow("1.2.3.4", now) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if th.allow("1.2.3.4", now) {
		t.Error("4th attempt in-window should be blocked")
	}
	if !th.allow("5.6.7.8", now) {
		t.Error("a different IP has its own budget and should be allowed")
	}
}

func TestThrottleWindowExpires(t *testing.T) {
	th := NewThrottle(2, time.Minute)
	t0 := time.Now()
	th.allow("ip", t0)
	th.allow("ip", t0)
	if th.allow("ip", t0) {
		t.Error("third attempt in-window should be blocked")
	}
	if !th.allow("ip", t0.Add(2*time.Minute)) {
		t.Error("after the window the old attempts prune and it should allow again")
	}
}

func TestThrottleGuardReturns429(t *testing.T) {
	th := NewThrottle(2, time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := th.Guard(next)
	call := func() (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = "9.9.9.9:5555"
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("Retry-After")
	}
	if c, _ := call(); c != http.StatusOK {
		t.Fatalf("first attempt = %d, want 200", c)
	}
	if c, _ := call(); c != http.StatusOK {
		t.Fatalf("second attempt = %d, want 200", c)
	}
	c, retry := call()
	if c != http.StatusTooManyRequests {
		t.Errorf("third attempt = %d, want 429", c)
	}
	if retry == "" {
		t.Error("429 should carry a Retry-After header")
	}
}
