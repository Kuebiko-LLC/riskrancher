// File: RiskRancher/pro/internal/license/manager.go
package license

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// Claims defines the data embedded inside the signed license key
type Claims struct {
	Company string `json:"company"`
	Expires int64  `json:"expires"` // Unix timestamp
}

// Manager holds the global license state for the running instance
type Manager struct {
	publicKey *rsa.PublicKey
	isActive  bool
	company   string
}

// NewManager returns a license manager for the open-source edition: it boots
// already active, so every Pro and Auditor feature is unlocked with no key and
// no network calls. The RSA verification code below is kept intact but dormant
// so a commercial fork can re-enable gating by booting with isActive: false.
func NewManager(pubKey *rsa.PublicKey) *Manager {
	return &Manager{
		publicKey: pubKey,
		isActive:  true,
		company:   "RiskRancher",
	}
}

// LoadFromEnv checks for the Docker/CI environment variable
func (m *Manager) LoadFromEnv() error {
	token := os.Getenv("RR_PRO_LICENSE_KEY")
	if token == "" {
		return nil // No env var provided, just boot in Free mode quietly
	}

	claims, err := m.VerifyToken(token)
	if err != nil {
		return err // Token was provided but invalid
	}

	// Success! Lock the app into Enterprise Mode
	m.isActive = true
	m.company = claims.Company
	return nil
}

// VerifyToken performs the offline mathematical check
func (m *Manager) VerifyToken(tokenString string) (*Claims, error) {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	parts := strings.Split(tokenString, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed license key format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid license encoding")
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	hashed := sha256.Sum256(payloadBytes)
	err = rsa.VerifyPKCS1v15(m.publicKey, crypto.SHA256, hashed[:], signatureBytes)
	if err != nil {
		return nil, errors.New("license signature invalid or tampered")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("corrupted license data")
	}

	if time.Now().Unix() > claims.Expires {
		return nil, errors.New("license expired")
	}

	return &claims, nil
}

func (m *Manager) IsEnterpriseActive() bool {
	return m.isActive
}

func (m *Manager) GetCompanyName() string {
	return m.company
}

// Activate dynamically validates and applies a license key in real-time
func (m *Manager) Activate(tokenString string) error {
	claims, err := m.VerifyToken(tokenString)
	if err != nil {
		return err
	}

	m.isActive = true
	m.company = claims.Company
	return nil
}
