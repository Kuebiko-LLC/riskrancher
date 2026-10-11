package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireAuthMiddleware(t *testing.T) {
	h, db := setupTestAuth(t)
	defer db.Close()

	user, err := h.Store.CreateUser(context.Background(), "vip@RiskRancher.com", "Wyatt Earp", "fake_hash", "Sheriff")
	if err != nil {
		t.Fatalf("Failed to seed test user: %v", err)
	}

	validToken := "valid_test_token_123"
	expiresAt := time.Now().Add(1 * time.Hour)
	err = h.Store.CreateSession(context.Background(), validToken, user.ID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to seed test session: %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the VIP room"))
	})
	protectedHandler := h.RequireAuth(dummyHandler)

	tests := []struct {
		name           string
		cookieName     string
		cookieValue    string
		expectedStatus int
	}{
		{"Missing Cookie", "", "", http.StatusUnauthorized},
		{"Wrong Cookie Name", "wrong_name", validToken, http.StatusUnauthorized},
		{"Invalid Token", "session_token", "fake_invalid_token", http.StatusUnauthorized},
		{"Valid Token", "session_token", validToken, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			if tt.cookieName != "" {
				req.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.cookieValue})
			}

			rr := httptest.NewRecorder()
			protectedHandler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}
