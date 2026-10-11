package auth

import (
	"net/http"
)

// RequireRole acts as the checker
func (h *Handler) RequireRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			userIDVal := r.Context().Value(UserIDKey)
			if userIDVal == nil {
				http.Error(w, "Unauthorized: No user context", http.StatusUnauthorized)
				return
			}

			userID, ok := userIDVal.(int)
			if !ok {
				http.Error(w, "Internal Server Error: Invalid user context", http.StatusInternalServerError)
				return
			}

			user, err := h.Store.GetUserByID(r.Context(), userID)
			if err != nil {
				http.Error(w, "Forbidden: User not found", http.StatusForbidden)
				return
			}

			if user.GlobalRole != requiredRole {
				http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole allows access if the user has ANY of the provided roles.
func (h *Handler) RequireAnyRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			userIDVal := r.Context().Value(UserIDKey)
			if userIDVal == nil {
				http.Error(w, "Unauthorized: No user context", http.StatusUnauthorized)
				return
			}

			userID, ok := userIDVal.(int)
			if !ok {
				http.Error(w, "Internal Server Error: Invalid user context", http.StatusInternalServerError)
				return
			}

			user, err := h.Store.GetUserByID(r.Context(), userID)
			if err != nil {
				http.Error(w, "Forbidden: User not found", http.StatusForbidden)
				return
			}

			for _, role := range allowedRoles {
				if user.GlobalRole == role {
					// Match found! Open the door.
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
		})
	}
}
