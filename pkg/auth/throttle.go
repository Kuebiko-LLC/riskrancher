package auth

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Auth throttle defaults. Fail-closed bootstrap values: a client gets maxAuthAttempts
// tries within authWindow before the public auth endpoints answer 429. Tunable later
// via app config.
const (
	maxAuthAttempts = 10
	authWindow      = time.Minute
)

// Throttle is an in-memory, per-client sliding-window limiter for the public auth
// endpoints (login, register), so credential stuffing cannot hammer them unbounded
// (CWE-307). State lives for the process; a restart clears it, which is acceptable for
// a brute-force cap.
type Throttle struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewThrottle builds a limiter allowing max attempts per window.
func NewThrottle(max int, window time.Duration) *Throttle {
	return &Throttle{hits: map[string][]time.Time{}, max: max, window: window}
}

// NewLoginThrottle is the default auth limiter.
func NewLoginThrottle() *Throttle { return NewThrottle(maxAuthAttempts, authWindow) }

// allow records an attempt for key at now and reports whether it is within budget. It
// prunes attempts older than the window as it goes, so the map does not grow unbounded
// for an active key.
func (t *Throttle) allow(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := now.Add(-t.window)
	kept := t.hits[key][:0]
	for _, ts := range t.hits[key] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= t.max {
		t.hits[key] = kept
		return false
	}
	t.hits[key] = append(kept, now)
	return true
}

// Guard wraps a handler so a client over its budget gets 429 before the handler runs.
func (t *Throttle) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !t.allow(clientKey(r), time.Now()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(t.window.Seconds())))
			http.Error(w, "Too many attempts, slow down", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientKey is the throttle key: the client IP from RemoteAddr. X-Forwarded-For is not
// trusted, because it is attacker-settable and would let a brute-forcer rotate keys.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
