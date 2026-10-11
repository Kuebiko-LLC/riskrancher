package auth

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

// M6: the session cookie's Secure flag follows the request, so it is set over
// HTTPS (direct TLS or behind an https proxy) but not over plain localhost HTTP.
func TestSecureRequest(t *testing.T) {
	plain := httptest.NewRequest("POST", "/api/auth/login", nil)
	if secureRequest(plain) {
		t.Errorf("plain HTTP request should not be marked secure")
	}

	tlsReq := httptest.NewRequest("POST", "/api/auth/login", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	if !secureRequest(tlsReq) {
		t.Errorf("TLS request should be marked secure")
	}

	proxied := httptest.NewRequest("POST", "/api/auth/login", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if !secureRequest(proxied) {
		t.Errorf("request behind an https proxy should be marked secure")
	}
}
