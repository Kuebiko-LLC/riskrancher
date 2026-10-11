// File: RiskRancher/pro/api/audit.go
package middleware

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// EnterpriseAuditLogger catches panics and logs structured JSON for SIEMs, plus immutable SQLite logs.
func EnterpriseAuditLogger(proStore storage.ProStoreInterface, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
			}

			// 1. PANIC RECOVERER
			defer func() {
				if err := recover(); err != nil {
					rec.statusCode = http.StatusInternalServerError
					stackTrace := string(debug.Stack())

					// 🚀 THE UPGRADE: Structured SIEM Logging
					logger.Error("FATAL PANIC RECOVERED",
						slog.Any("error", err),
						slog.String("path", r.URL.Path),
						slog.String("method", r.Method),
						slog.String("ip", r.RemoteAddr),
					)

					http.Error(rec, "Internal Server Error", http.StatusInternalServerError)
					proStore.LogAuditAction(r.Context(), "System", r.Method, r.URL.Path, 500, stackTrace, r.RemoteAddr)
				}
			}()

			next.ServeHTTP(rec, r)
			duration := time.Since(start)

			// 🚀 FIX: Actually extract the User from the context!
			actor := "Unknown User"
			if userIDVal := r.Context().Value(auth.UserIDKey); userIDVal != nil {
				userID := userIDVal.(int)
				// Fetch the user to get their email/name
				user, err := proStore.GetUserByID(r.Context(), userID)
				if err == nil {
					actor = user.Email // Or user.FullName if you prefer!
				} else {
					actor = fmt.Sprintf("User ID: %d", userID)
				}
			}

			// 2. Log Errors (400s/500s)
			if rec.statusCode >= 400 {
				errorMsg := rec.body.String()

				logger.Warn("HTTP Request Failed",
					slog.Int("status", rec.statusCode),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("actor", actor),
					slog.Duration("latency", duration),
					slog.String("error", errorMsg),
				)

				proStore.LogAuditAction(r.Context(), actor, r.Method, r.URL.Path, rec.statusCode, errorMsg, r.RemoteAddr)

				// 3. Log Mutating Actions (POST, PATCH, DELETE)
			} else if r.Method != http.MethodGet {
				logger.Info("Mutating Action Successful",
					slog.Int("status", rec.statusCode),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("actor", actor),
					slog.Duration("latency", duration),
				)

				proStore.LogAuditAction(r.Context(), actor, r.Method, r.URL.Path, rec.statusCode, "Success", r.RemoteAddr)
			}
		})
	}
}
