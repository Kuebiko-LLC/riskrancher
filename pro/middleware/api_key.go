// File: RiskRancher/pro/api/api_key.go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// ServiceAccountAuth middleware intercepts Bearer tokens for automated API access
func ServiceAccountAuth(store storage.ProStoreInterface) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			// If no bearer token, pass through to normal Web UI session auth (handled elsewhere)
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")
			hashedToken := storage.HashToken(rawToken)

			// Lookup the token in the database
			apiKey, err := store.GetAPIKeyByHash(r.Context(), hashedToken)
			if err != nil {
				http.Error(w, `{"error": "Unauthorized: Invalid or Revoked API Key"}`, http.StatusUnauthorized)
				return
			}

			// 🤠 Inject the Service Account Context
			// Depending on your core.ContextKeys, adjust these string keys.
			ctx := context.WithValue(r.Context(), "user_id", apiKey.CreatedBy)
			ctx = context.WithValue(ctx, "role", apiKey.Permissions) // e.g., WriteOnly, FullAdmin
			ctx = context.WithValue(ctx, "is_service_account", true)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
