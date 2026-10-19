package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"golang.org/x/crypto/bcrypt"
)

// ValidatePassword enforces a minimum length and bcrypt's 72-byte input limit, so a
// password is neither trivially weak nor silently truncated by bcrypt (RR-L3).
func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

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
