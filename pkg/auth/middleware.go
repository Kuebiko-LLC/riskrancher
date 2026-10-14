package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

type contextKey string

const UserIDKey contextKey = "user_id"

// RequireAuth admits a request on a session cookie or on an API key sent as
// "Authorization: Bearer <key>". A key acts as the user who created it, so
// role checks downstream see that user's role; a ReadOnly key may only GET.
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			key, err := h.Store.GetAPIKeyByHash(r.Context(), datastore.HashToken(strings.TrimSpace(raw)))
			if err != nil {
				http.Error(w, "Unauthorized: invalid or revoked API key", http.StatusUnauthorized)
				return
			}
			if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
				http.Error(w, "Unauthorized: API key expired", http.StatusUnauthorized)
				return
			}
			if key.Permissions == "ReadOnly" && r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "Forbidden: read-only API key", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), UserIDKey, key.CreatedBy)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized: Missing session cookie", http.StatusUnauthorized)
			return
		}

		session, err := h.Store.GetSession(r.Context(), cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
			return
		}

		if session.ExpiresAt.Before(time.Now()) {
			http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, session.UserID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireUIAuth checks for a valid session and redirects to /login if it fails,
func (h *Handler) RequireUIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, err := h.Store.GetSession(r.Context(), cookie.Value)
		if err != nil || session.ExpiresAt.Before(time.Now()) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, session.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
