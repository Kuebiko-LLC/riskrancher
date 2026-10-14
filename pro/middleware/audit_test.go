// File: RiskRancher/pro/api/audit_test.go
package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// MockStore intercepts database calls for testing
type MockAuditStore struct {
	storage.ProStoreInterface // Embed the interface to satisfy the signature
	Logs                      []map[string]any
}

func (m *MockAuditStore) LogAuditAction(ctx context.Context, actor, action, resource string, statusCode int, errorDetails, ip string) error {
	m.Logs = append(m.Logs, map[string]any{
		"actor":    actor,
		"action":   action,
		"resource": resource,
		"status":   statusCode,
		"error":    errorDetails,
	})
	return nil
}

func TestAuditLogger_BDD(t *testing.T) {
	// Silence standard output for tests
	nopLogger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))

	t.Run("Given a handler that panics, When a request is made, Then it returns 500 and logs the stack trace", func(t *testing.T) {
		mockStore := &MockAuditStore{}
		middleware := AuditLogger(mockStore, nopLogger)

		// 1. Arrange: A handler guaranteed to explode
		panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("simulated nil pointer dereference")
		})

		req := httptest.NewRequest(http.MethodPost, "/api/pro/dangerous", nil)
		w := httptest.NewRecorder()

		// 2. Act: Run the request through the middleware
		middleware(panicHandler).ServeHTTP(w, req)

		// 3. Assert: Did it survive and log properly?
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected HTTP 500, got %d", w.Code)
		}
		if len(mockStore.Logs) != 1 {
			t.Fatalf("Expected exactly 1 audit log, got %d", len(mockStore.Logs))
		}
		if mockStore.Logs[0]["status"] != 500 {
			t.Errorf("Expected DB log status to be 500, got %v", mockStore.Logs[0]["status"])
		}
	})

	t.Run("Given a successful POST request, When it completes, Then it logs the mutating action for compliance", func(t *testing.T) {
		mockStore := &MockAuditStore{}
		middleware := AuditLogger(mockStore, nopLogger)

		// 1. Arrange: A normal handler
		successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status":"created"}`))
		})

		req := httptest.NewRequest(http.MethodPost, "/api/pro/triage-rules", nil)
		w := httptest.NewRecorder()

		// 2. Act
		middleware(successHandler).ServeHTTP(w, req)

		// 3. Assert
		if w.Code != http.StatusCreated {
			t.Errorf("Expected HTTP 201, got %d", w.Code)
		}
		if len(mockStore.Logs) != 1 {
			t.Fatalf("Expected exactly 1 audit log, got %d", len(mockStore.Logs))
		}
		if mockStore.Logs[0]["error"] != "Success" {
			t.Errorf("Expected DB log to record 'Success', got %v", mockStore.Logs[0]["error"])
		}
	})
}
