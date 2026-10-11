package domain

import "time"

type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	FullName     string    `json:"full_name"`
	PasswordHash string    `json:"-"`
	GlobalRole   string    `json:"global_role"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}
type Session struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
