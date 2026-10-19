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

// ActorKey names who is acting when there is no session: the owner behind a
// link. The audit log reads it before it looks for a user.
const ActorKey contextKey = "actor"

// RequireAuth admits a request on a session cookie or on an API key sent as
// "Authorization: Bearer <key>". A key acts as the user who created it, so
// role checks downstream see that user's role; a ReadOnly key may only GET.
// refuse answers an auth failure and puts it on the record. When the
// request already carries a user, the row names them.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, actor, msg string, code int) {
	if uid, ok := r.Context().Value(UserIDKey).(int); ok {
		if u, err := h.Store.GetUserByID(r.Context(), uid); err == nil {
			actor = u.Email
		}
	}
	h.Store.LogAuditAction(r.Context(), actor, r.Method, r.URL.Path, code, msg, r.RemoteAddr)
	http.Error(w, msg, code)
}

func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			key, err := h.Store.GetAPIKeyByHash(r.Context(), datastore.HashToken(strings.TrimSpace(raw)))
			if err != nil {
				h.refuse(w, r, "Unknown User", "Unauthorized: invalid or revoked API key", http.StatusUnauthorized)
				return
			}
			if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
				h.refuse(w, r, "Unknown User", "Unauthorized: API key expired", http.StatusUnauthorized)
				return
			}
			if key.Permissions == "ReadOnly" && r.Method != http.MethodGet && r.Method != http.MethodHead {
				h.refuse(w, r, "Unknown User", "Forbidden: read-only API key", http.StatusForbidden)
				return
			}
			// An Ingest key is for scanners pushing findings. It acts as its creator for
			// ownership and audit, but may reach ONLY the ingest endpoints, so a leaked
			// scanner key cannot touch user, config or key-management routes.
			if key.Permissions == "Ingest" && !(r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/ingest")) {
				h.refuse(w, r, "Unknown User", "Forbidden: ingest-only API key", http.StatusForbidden)
				return
			}
			// A key is only as alive as the person it acts for
			if owner, err := h.Store.GetUserByID(r.Context(), key.CreatedBy); err != nil || !owner.IsActive {
				h.refuse(w, r, "Unknown User", "Unauthorized: API key owner is not active", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), UserIDKey, key.CreatedBy)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			h.refuse(w, r, "Unknown User", "Unauthorized: Missing session cookie", http.StatusUnauthorized)
			return
		}

		session, err := h.Store.GetSession(r.Context(), cookie.Value)
		if err != nil {
			h.refuse(w, r, "Unknown User", "Unauthorized: Invalid session", http.StatusUnauthorized)
			return
		}

		if session.ExpiresAt.Before(time.Now()) {
			h.refuse(w, r, "Unknown User", "Unauthorized: Session expired", http.StatusUnauthorized)
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
