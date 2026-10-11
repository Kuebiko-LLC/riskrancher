// File: RiskRancher/pro/api/license.go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pro/license"
)

// LicenseClaims defines the data embedded inside the signed license key
type LicenseClaims struct {
	Company string `json:"company"`
	Expires int64  `json:"expires"` // Unix timestamp
}

func GlobalLicenseGate(manager *license.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If they have a valid license, let them through normally
		if manager.IsEnterpriseActive() {
			next.ServeHTTP(w, r)
			return
		}

		// If unlicensed, ONLY allow access to the setup screen and CSS/JS
		path := r.URL.Path
		if path == "/setup" || path == "/api/pro/activate" || strings.HasPrefix(path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		// Block everything else and force them to the activation screen
		http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
	})
}

// RequireProLicense intercepts requests and verifies the offline RSA-signed token.
// It first checks if a valid license was loaded at boot via Environment Variables.
// If not, it falls back to checking the HTTP headers.
func RequireProLicense(manager *license.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// 1. FAST PATH: Was a valid license injected via CI/CD Environment Variable at boot?
			if manager.IsEnterpriseActive() {
				ctx := context.WithValue(r.Context(), "license_company", manager.GetCompanyName())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// 2. FALLBACK: Check the HTTP Header (for users who pasted it into the UI)
			tokenString := r.Header.Get("X-RiskRancher-License")
			if tokenString == "" {
				http.Error(w, `{"error": "Activation Required. Visit riskrancher.com/pricing"}`, http.StatusPaymentRequired)
				return
			}

			// Clean up Bearer prefix if they used it
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")

			// 3. Verify the token using the Manager's robust offline math
			claims, err := manager.VerifyToken(tokenString)
			if err != nil {
				if strings.Contains(err.Error(), "expired") {
					http.Error(w, `{"error": "License Expired. Please renew."}`, http.StatusPaymentRequired)
					return
				}
				http.Error(w, `{"error": "Invalid or Tampered License Signature"}`, http.StatusForbidden)
				return
			}

			// 4. Success! Inject company identity into context and proceed
			ctx := context.WithValue(r.Context(), "license_company", claims.Company)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
