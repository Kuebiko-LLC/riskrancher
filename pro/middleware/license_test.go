package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pro/license"
	"github.com/Kuebiko-LLC/riskrancher/pro/middleware"
)

// In the open-source edition the license manager boots active, so the Pro-route
// gate passes every request through and injects the community company name.
// The dormant 402/403 paywall paths are covered by the manager's crypto tests.
func TestOpenEditionProRouteGate_BDD(t *testing.T) {
	manager := license.NewManager(nil) // open edition: active, no public key needed
	authMiddleware := middleware.RequireProLicense(manager)

	proHandler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		company, _ := r.Context().Value("license_company").(string)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to Enterprise, " + company))
	}))

	cases := []struct {
		name   string
		header string
	}{
		{"with no license header", ""},
		{"with a junk license header", "not-a-real-token"},
		{"with a bearer-prefixed junk header", "Bearer still-not-real"},
	}

	t.Run("Given a request to a Pro route in the open edition", func(t *testing.T) {
		for _, tc := range cases {
			t.Run("When it arrives "+tc.name+", Then the route unlocks", func(t *testing.T) {
				req := httptest.NewRequest("GET", "/api/pro/triage-rules", nil)
				if tc.header != "" {
					req.Header.Set("X-RiskRancher-License", tc.header)
				}
				rr := httptest.NewRecorder()

				proHandler.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("Expected 200 OK, got %d", rr.Code)
				}
				if rr.Body.String() != "Welcome to Enterprise, RiskRancher" {
					t.Errorf("Expected RiskRancher context injection, got: %s", rr.Body.String())
				}
			})
		}
	})
}

// GlobalLicenseGate must not redirect anyone to /setup in the open edition.
func TestOpenEditionGlobalGate_BDD(t *testing.T) {
	manager := license.NewManager(nil)
	gated := middleware.GlobalLicenseGate(manager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("dashboard"))
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	gated.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected the dashboard to serve (200), got %d (a %q redirect means the paywall leaked)", rr.Code, rr.Header().Get("Location"))
	}
}
