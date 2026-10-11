package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const SessionCookieName = "session_token"

// RegisterRequest represents the JSON payload expected for user registration.
type RegisterRequest struct {
	Email      string `json:"email"`
	FullName   string `json:"full_name"`
	Password   string `json:"password"`
	GlobalRole string `json:"global_role"`
}

// LoginRequest represents the JSON payload expected for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HandleRegister processes new user signups.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	count, err := h.Store.GetUserCount(r.Context())
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Error(w, "Forbidden: System already initialized. Contact your Sheriff for an account.", http.StatusForbidden)
		return
	}

	req.GlobalRole = "Sheriff"

	if req.Email == "" || req.Password == "" || req.FullName == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user, err := h.Store.CreateUser(r.Context(), req.Email, req.FullName, hashedPassword, req.GlobalRole)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// HandleLogin authenticates a user and issues a session cookie.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	user, err := h.Store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !CheckPasswordHash(req.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := GenerateSessionToken()
	if err != nil {
		http.Error(w, "Failed to generate session", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if err := h.Store.CreateSession(r.Context(), token, user.ID, expiresAt); err != nil {
		http.Error(w, "Failed to persist session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to TRUE in production for HTTPS!
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// HandleLogout destroys the user's session in the database and clears their cookie.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)

	if err == nil && cookie.Value != "" {
		_ = h.Store.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true, // Ensures it's only sent over HTTPS
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully logged out",
	})
}
