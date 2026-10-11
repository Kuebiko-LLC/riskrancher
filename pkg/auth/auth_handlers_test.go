package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

func setupTestAuth(t *testing.T) (*Handler, *sql.DB) {
	db := datastore.InitDB(":memory:")

	store := datastore.NewSQLiteStore(db)

	h := NewHandler(store)

	return h, db
}

func TestAuthHandlers(t *testing.T) {
	a, db := setupTestAuth(t)
	defer db.Close()

	t.Run("Successful Registration", func(t *testing.T) {
		payload := map[string]string{
			"email":       "admin@RiskRancher.com",
			"full_name":   "Doc Holliday",
			"password":    "SuperSecretPassword123!",
			"global_role": "Sheriff", // Use a valid role!
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		a.HandleRegister(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("Expected 201 Created for registration, got %d", rr.Code)
		}
	})

	t.Run("Successful Login Issues Cookie", func(t *testing.T) {
		payload := map[string]string{
			"email":    "admin@RiskRancher.com",
			"password": "SuperSecretPassword123!",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		a.HandleLogin(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for successful login, got %d", rr.Code)
		}

		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatalf("Expected a session cookie to be set, but none was found")
		}
		if cookies[0].Name != "session_token" {
			t.Errorf("Expected cookie named 'session_token', got '%s'", cookies[0].Name)
		}
	})

	t.Run("Failed Login Rejects Access", func(t *testing.T) {
		payload := map[string]string{
			"email":    "admin@RiskRancher.com",
			"password": "WrongPassword!",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		a.HandleLogin(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("Expected 401 Unauthorized for wrong password, got %d", rr.Code)
		}
	})
}

func TestHandleLogout(t *testing.T) {
	a, db := setupTestAuth(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)

	cookie := &http.Cookie{
		Name:  SessionCookieName,
		Value: "fake-session-token-123",
	}
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	a.HandleLogout(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}
