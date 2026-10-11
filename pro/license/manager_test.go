package license_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pro/license"
)

// Helper function to mint test tokens (same shape as the mint command).
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

// The open-source edition boots unlocked: NewManager is active out of the gate,
// no key required, and an invalid key never downgrades it.
func TestOpenEditionManager_BDD(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	t.Run("Given a freshly booted open-source manager", func(t *testing.T) {
		manager := license.NewManager(publicKey)

		t.Run("Then every Pro feature is active with no key", func(t *testing.T) {
			if !manager.IsEnterpriseActive() {
				t.Errorf("Expected the open edition to boot ACTIVE")
			}
			if manager.GetCompanyName() != "RiskRancher" {
				t.Errorf("Expected 'RiskRancher', got: %s", manager.GetCompanyName())
			}
		})
	})

	t.Run("Given RR_PRO_LICENSE_KEY carries a VALID token", func(t *testing.T) {
		validToken := mintTestToken(privateKey, "Acme CI/CD", time.Now().Add(24*time.Hour))
		os.Setenv("RR_PRO_LICENSE_KEY", validToken)
		defer os.Unsetenv("RR_PRO_LICENSE_KEY")

		manager := license.NewManager(publicKey)
		err := manager.LoadFromEnv()

		t.Run("Then it labels the banner with the company and stays active", func(t *testing.T) {
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if !manager.IsEnterpriseActive() {
				t.Errorf("Expected active")
			}
			if manager.GetCompanyName() != "Acme CI/CD" {
				t.Errorf("Expected company 'Acme CI/CD', got: %s", manager.GetCompanyName())
			}
		})
	})

	t.Run("Given RR_PRO_LICENSE_KEY carries an invalid token", func(t *testing.T) {
		expiredToken := mintTestToken(privateKey, "Acme CI/CD", time.Now().Add(-24*time.Hour))
		os.Setenv("RR_PRO_LICENSE_KEY", expiredToken)
		defer os.Unsetenv("RR_PRO_LICENSE_KEY")

		manager := license.NewManager(publicKey)
		err := manager.LoadFromEnv()

		t.Run("Then the bad key is surfaced but features stay unlocked", func(t *testing.T) {
			if err == nil {
				t.Fatalf("Expected an expiration error to be reported")
			}
			if !manager.IsEnterpriseActive() {
				t.Errorf("Open edition must never lock itself over a bad key")
			}
		})
	})
}

// The RSA verification code is kept intact (dormant) so a commercial fork can
// re-gate. This proves the offline math still rejects bad tokens.
func TestVerifyTokenCryptoStillSound_BDD(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	manager := license.NewManager(&privateKey.PublicKey)

	t.Run("A validly signed, unexpired token verifies", func(t *testing.T) {
		tok := mintTestToken(privateKey, "Stark Industries", time.Now().Add(365*24*time.Hour))
		claims, err := manager.VerifyToken(tok)
		if err != nil {
			t.Fatalf("Expected valid token to verify, got: %v", err)
		}
		if claims.Company != "Stark Industries" {
			t.Errorf("Expected 'Stark Industries', got: %s", claims.Company)
		}
	})

	t.Run("An expired token is rejected", func(t *testing.T) {
		tok := mintTestToken(privateKey, "Acme Corp", time.Now().Add(-1*time.Hour))
		if _, err := manager.VerifyToken(tok); err == nil {
			t.Errorf("Expected expired token to be rejected")
		}
	})

	t.Run("A tampered token is rejected", func(t *testing.T) {
		tok := mintTestToken(privateKey, "Acme Corp", time.Now().Add(24*time.Hour))
		if _, err := manager.VerifyToken("A" + tok[1:]); err == nil {
			t.Errorf("Expected tampered token to be rejected")
		}
	})
}
