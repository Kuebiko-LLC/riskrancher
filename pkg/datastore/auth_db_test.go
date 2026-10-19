package datastore

import (
	"context"
	"testing"
	"time"
)

func TestUserAndSessionLifecycle(t *testing.T) {
	store := setupTestDB(t)
	defer store.DB.Close()

	_, err := store.DB.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, full_name TEXT, password_hash TEXT, global_role TEXT, is_active BOOLEAN DEFAULT 1);
		CREATE TABLE sessions (session_token TEXT PRIMARY KEY, user_id INTEGER, expires_at DATETIME);
	`)

	ctx := context.Background()

	user, err := store.CreateUser(ctx, "admin@RiskRancher.com", "doc", "fake_bcrypt_hash", "Admin")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	if user.ID == 0 {
		t.Errorf("Expected database to return a valid auto-incremented ID, got 0")
	}

	_, err = store.CreateUser(ctx, "admin@RiskRancher.com", "doc", "another_hash", "Analyst")
	if err == nil {
		t.Fatalf("Security Failure: Database allowed a duplicate email address!")
	}

	fetchedUser, err := store.GetUserByEmail(ctx, "admin@RiskRancher.com")
	if err != nil {
		t.Fatalf("Failed to fetch user by email: %v", err)
	}
	if fetchedUser.GlobalRole != "Admin" {
		t.Errorf("Expected role 'Admin', got '%s'", fetchedUser.GlobalRole)
	}

	expires := time.Now().Add(24 * time.Hour)
	err = store.CreateSession(ctx, "fake_secure_token", user.ID, expires)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session, err := store.GetSession(ctx, "fake_secure_token")
	if err != nil {
		t.Fatalf("Failed to retrieve session: %v", err)
	}
	if session.UserID != user.ID {
		t.Errorf("Session mapped to wrong user! Expected %d, got %d", user.ID, session.UserID)
	}

	userByID, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to fetch user by ID: %v", err)
	}
	if userByID.Email != user.Email {
		t.Errorf("GetUserByID returned wrong user. Expected %s, got %s", user.Email, userByID.Email)
	}

	newHash := "new_secure_bcrypt_hash_999"
	err = store.UpdateUserPassword(ctx, user.ID, newHash)
	if err != nil {
		t.Fatalf("Failed to update user password: %v", err)
	}

	updatedUser, _ := store.GetUserByID(ctx, user.ID)
	if updatedUser.PasswordHash != newHash {
		t.Errorf("Password hash did not update in the database")
	}
}

// Changing a password must revoke the user's existing sessions (RR-L2).
func TestUpdateUserPasswordRevokesSessions(t *testing.T) {
	store := setupTestDB(t) // InitDB applies the full schema, incl. users + sessions
	defer store.DB.Close()
	ctx := context.Background()
	user, err := store.CreateUser(ctx, "u@rr.test", "U", "oldhash", "Sheriff")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, "tok-123", user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(ctx, "tok-123"); err != nil {
		t.Fatalf("session should exist before the change: %v", err)
	}
	if err := store.UpdateUserPassword(ctx, user.ID, "newhash"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(ctx, "tok-123"); err == nil {
		t.Error("changing the password should revoke the user's sessions")
	}
}
