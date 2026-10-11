// File: RiskRancher/pro/internal/admin/license_handler_test.go
package admin_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pro/admin"
	"github.com/Kuebiko-LLC/riskrancher/pro/license"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

// Helper function to reliably mint tokens for our UI tests
func mintTestToken(privateKey *rsa.PrivateKey, company string, expires time.Time) string {
	claims := license.Claims{
		Company: company,
		Expires: expires.Unix(),
	}
	payloadBytes, _ := json.Marshal(claims)
	hashed := sha256.Sum256(payloadBytes)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	encodedSig := base64.RawURLEncoding.EncodeToString(signature)

	return encodedPayload + "." + encodedSig
}

func TestActivateLicenseAPI_BDD(t *testing.T) {
	// 1. Setup the Offline Cryptography
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	manager := license.NewManager(publicKey)

	// 2. Setup the In-Memory Database
	db := core.InitDB(":memory:")
	defer db.Close()
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	// 3. Setup the Target Handler
	proHandler := admin.NewProHandler(store)
	targetEndpoint := proHandler.HandleActivateLicense(manager)

	t.Run("Given an unlicensed RiskRancher/pro instance", func(t *testing.T) {

		t.Run("When the user submits a VALID license key via the UI", func(t *testing.T) {
			validKey := mintTestToken(privateKey, "Wayne Enterprises", time.Now().Add(24*time.Hour))

			// Build the JSON request body
			reqBody, _ := json.Marshal(map[string]string{"license_key": validKey})
			req := httptest.NewRequest("POST", "/api/pro/activate", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			targetEndpoint.ServeHTTP(rr, req)

			t.Run("Then it returns 200 OK", func(t *testing.T) {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected 200 OK, got %d", rr.Code)
				}
			})

			t.Run("Then the License Manager is dynamically activated in memory", func(t *testing.T) {
				if !manager.IsEnterpriseActive() {
					t.Errorf("Expected manager to be active, but it was not")
				}
				if manager.GetCompanyName() != "Wayne Enterprises" {
					t.Errorf("Expected Wayne Enterprises, got %s", manager.GetCompanyName())
				}
			})

			t.Run("Then the License Key is permanently saved to the SQLite database", func(t *testing.T) {
				savedKey, err := store.GetLicenseKey(context.Background())
				if err != nil {
					t.Fatalf("Failed to fetch key from DB: %v", err)
				}
				if savedKey != validKey {
					t.Errorf("Expected saved key to match submitted key")
				}
			})
		})

		t.Run("When the user submits an EXPIRED license key", func(t *testing.T) {
			expiredKey := mintTestToken(privateKey, "LexCorp", time.Now().Add(-24*time.Hour))
			reqBody, _ := json.Marshal(map[string]string{"license_key": expiredKey})
			req := httptest.NewRequest("POST", "/api/pro/activate", bytes.NewBuffer(reqBody))
			rr := httptest.NewRecorder()

			targetEndpoint.ServeHTTP(rr, req)

			t.Run("Then it rejects the request with 403 Forbidden", func(t *testing.T) {
				if rr.Code != http.StatusForbidden {
					t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
				}
			})
		})

		t.Run("When the user submits a MALFORMED JSON payload", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/pro/activate", bytes.NewBuffer([]byte(`{bad json}`)))
			rr := httptest.NewRecorder()

			targetEndpoint.ServeHTTP(rr, req)

			t.Run("Then it rejects the request with 400 Bad Request", func(t *testing.T) {
				if rr.Code != http.StatusBadRequest {
					t.Errorf("Expected 400 Bad Request, got %d", rr.Code)
				}
			})
		})
	})
}
