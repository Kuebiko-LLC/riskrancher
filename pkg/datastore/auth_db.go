package datastore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// ErrNotFound is a standard error we can use across our handlers
var ErrNotFound = errors.New("record not found")

func (s *SQLiteStore) CreateUser(ctx context.Context, email, fullName, passwordHash, globalRole string) (*domain.User, error) {
	query := `INSERT INTO users (email, full_name, password_hash, global_role) VALUES (?, ?, ?, ?)`

	result, err := s.DB.ExecContext(ctx, query, email, fullName, passwordHash, globalRole)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	// Read the row back so the caller sees what the database holds: active, and when.
	return s.GetUserByID(ctx, int(id))
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	var created sql.NullTime
	query := "SELECT id, email, password_hash, full_name, global_role, COALESCE(is_active, 1), created_at FROM users WHERE email = ? AND is_active = 1"

	err := s.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.GlobalRole,
		&user.IsActive,
		&created,
	)
	user.CreatedAt = created.Time

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows // Bouncer says no (either wrong email, or deactivated)
		}
		return nil, err
	}

	return &user, nil
}

func (s *SQLiteStore) CreateSession(ctx context.Context, token string, userID int, expiresAt time.Time) error {
	query := `INSERT INTO sessions (session_token, user_id, expires_at) VALUES (?, ?, ?)`
	_, err := s.DB.ExecContext(ctx, query, token, userID, expiresAt)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, token string) (*domain.Session, error) {
	query := `SELECT session_token, user_id, expires_at FROM sessions WHERE session_token = ?`

	var session domain.Session
	err := s.DB.QueryRowContext(ctx, query, token).Scan(
		&session.Token,
		&session.UserID,
		&session.ExpiresAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &session, nil
}

// GetUserByID fetches a user's full record, including their role
func (s *SQLiteStore) GetUserByID(ctx context.Context, id int) (*domain.User, error) {
	query := `SELECT id, email, full_name, password_hash, global_role, COALESCE(is_active, 1), created_at FROM users WHERE id = ?`

	var user domain.User
	var created sql.NullTime
	err := s.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.FullName,
		&user.PasswordHash,
		&user.GlobalRole,
		&user.IsActive,
		&created,
	)
	user.CreatedAt = created.Time

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUserPassword allows an administrator to overwrite a forgotten password
func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, id int, newPasswordHash string) error {
	query := `UPDATE users SET password_hash = ? WHERE id = ?`

	_, err := s.DB.ExecContext(ctx, query, newPasswordHash, id)
	return err
}

// UpdateUserRole promotes or demotes a user by updating their global_role.
func (s *SQLiteStore) UpdateUserRole(ctx context.Context, id int, newRole string) error {
	query := `UPDATE users SET global_role = ? WHERE id = ?`

	_, err := s.DB.ExecContext(ctx, query, newRole, id)
	return err
}

// DeactivateUserAndReassign securely offboards a user, kicks them out
func (s *SQLiteStore) DeactivateUserAndReassign(ctx context.Context, userID int) error {
	var email string
	if err := s.DB.QueryRowContext(ctx, "SELECT email FROM users WHERE id = ?", userID).Scan(&email); err != nil {
		return err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `UPDATE users SET is_active = 0 WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM ticket_assignments WHERE assignee = ?`, email)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetUserCount returns the total number of registered users in the system.
func (s *SQLiteStore) GetUserCount(ctx context.Context) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLiteStore) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	// Notice the return type is now []*domain.User
	rows, err := s.DB.QueryContext(ctx, "SELECT id, email, full_name, global_role FROM users WHERE is_active = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.FullName, &u.GlobalRole); err == nil {
			users = append(users, &u) // Appending the memory address!
		}
	}
	return users, nil
}

// DeleteSession removes the token from the database so it can never be used again.
func (s *SQLiteStore) DeleteSession(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}
