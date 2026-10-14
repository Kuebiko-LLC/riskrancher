package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/Kuebiko-LLC/riskrancher/pro/models"
)

// GenerateSecureToken creates a 32-byte hex-encoded random string
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken generates a SHA-256 hash of the raw token
func HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

// CreateAPIKey generates a secure token, hashes it, stores the record, and returns the RAW token.
func (s *ProSQLiteStore) CreateAPIKey(ctx context.Context, key models.APIKey) (string, error) {
	rawToken, err := GenerateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	hashedToken := HashToken(rawToken)

	query := `
		INSERT INTO api_keys (token_hash, workspace_id, name, permissions, created_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		RETURNING id, created_at
	`
	err = s.db.QueryRowContext(
		ctx, query,
		hashedToken, key.WorkspaceID, key.Name, key.Permissions, key.CreatedBy, key.ExpiresAt,
	).Scan(&key.ID, &key.CreatedAt)

	if err != nil {
		return "", fmt.Errorf("failed to insert api key: %w", err)
	}

	// We return the raw token ONLY ONCE to the caller (so the UI can display it to the user)
	return rawToken, nil
}

// GetAPIKeyByHash retrieves an API key using the hashed version of the token provided in the Authorization header.
func (s *ProSQLiteStore) GetAPIKeyByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	query := `
		SELECT id, token_hash, workspace_id, name, permissions, created_by, created_at, expires_at, last_used_at
		FROM api_keys
		WHERE token_hash = ?
	`

	var k models.APIKey
	err := s.db.QueryRowContext(ctx, query, hash).Scan(
		&k.ID, &k.TokenHash, &k.WorkspaceID, &k.Name, &k.Permissions,
		&k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid or revoked API key")
		}
		return nil, err
	}

	// Async/Background task: Update last_used_at (could be decoupled for performance)
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, k.ID)

	return &k, nil
}
