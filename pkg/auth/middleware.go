package auth

import (
	"context"
	"net/http"
	"time"
)

type contextKey string

const UserIDKey contextKey = "user_id"

func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
