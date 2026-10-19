package auth

import (
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	valid := []string{"correct horse battery", strings.Repeat("a", 12), strings.Repeat("a", 72)}
	for _, p := range valid {
		if err := ValidatePassword(p); err != nil {
			t.Errorf("%q should be valid: %v", p, err)
		}
	}
	invalid := []string{"", "short", strings.Repeat("a", 11), strings.Repeat("a", 73)}
	for _, p := range invalid {
		if err := ValidatePassword(p); err == nil {
			t.Errorf("%q should be rejected", p)
		}
	}
}
