package auth

import (
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	password := "SuperSecretSOCPassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == password {
		t.Fatalf("Security failure: Hash matches plain text!")
	}
	if len(hash) == 0 {
		t.Fatalf("Hash is empty")
	}

	isValid := CheckPasswordHash(password, hash)
	if !isValid {
		t.Errorf("Expected valid password to match hash, but it failed")
	}

	isInvalid := CheckPasswordHash("WrongPassword!", hash)
	if isInvalid {
		t.Errorf("Security failure: Incorrect password returned true!")
	}
}

func TestGenerateSessionToken(t *testing.T) {

	token1, err1 := GenerateSessionToken()
	token2, err2 := GenerateSessionToken()

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to generate session tokens")
	}

	if len(token1) < 32 {
		t.Errorf("Token is too short for security standards: %d chars", len(token1))
	}

	if token1 == token2 {
		t.Errorf("CRITICAL: RNG generated the exact same token twice: %s", token1)
	}
}
