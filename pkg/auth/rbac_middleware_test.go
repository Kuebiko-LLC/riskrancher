package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireRoleMiddleware(t *testing.T) {
	a, db := setupTestAuth(t)
	defer db.Close()

	sheriff, _ := a.Store.CreateUser(context.Background(), "sheriff@ranch.com", "Wyatt Earp", "hash", "Sheriff")
	rangeHand, _ := a.Store.CreateUser(context.Background(), "hand@ranch.com", "Jesse James", "hash", "RangeHand")

	vipHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the Manager's Office"))
	})

	protectedHandler := a.RequireRole("Sheriff")(vipHandler)

	tests := []struct {
		name           string
		userID         int
		expectedStatus int
	}{
		{"Valid Sheriff Access", sheriff.ID, http.StatusOK},
		{"Denied RangeHand Access", rangeHand.ID, http.StatusForbidden},
		{"Unknown User", 9999, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/passwords", nil)

			ctx := context.WithValue(req.Context(), UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			protectedHandler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}
