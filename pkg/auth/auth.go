package auth

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"golang.org/x/crypto/bcrypt"
)

// Handler encapsulates all Identity and Access HTTP logic
type Handler struct {
	Store domain.Store
}

// NewHandler creates a new Auth Handler
func NewHandler(store domain.Store) *Handler {
	return &Handler{Store: store}
}

// HashPassword takes a plaintext password, automatically generates a secure salt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash securely compares a plaintext password with a stored bcrypt hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSessionToken creates a cryptographically secure random string
func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
