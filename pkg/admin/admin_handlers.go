package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
)

// PasswordResetRequest is the expected JSON payload
type PasswordResetRequest struct {
	NewPassword string `json:"new_password"`
}

// HandleAdminResetPassword allows a Sheriff to forcefully overwrite a user's password.
func (h *Handler) HandleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID in URL", http.StatusBadRequest)
		return
	}

	// A body with new_password sets that password. No body, as the admin
	// page sends, means generate one and hand it back once.
	var req PasswordResetRequest
	generated := false
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
	}
	if req.NewPassword == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "Could not generate a password", http.StatusInternalServerError)
			return
		}
		req.NewPassword = hex.EncodeToString(b)
		generated = true
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Internal server error during hashing", http.StatusInternalServerError)
		return
	}

	if err := h.Store.UpdateUserPassword(r.Context(), userID, hashedPassword); err != nil {
		http.Error(w, "Failed to update user password", http.StatusInternalServerError)
		return
	}

	if generated {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(req.NewPassword))
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successfully"})
}

type RoleUpdateRequest struct {
	GlobalRole string `json:"global_role"`
}

// HandleUpdateUserRole allows a Sheriff to promote or demote a user.
func (h *Handler) HandleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID in URL", http.StatusBadRequest)
		return
	}
	var req RoleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	validRoles := map[string]bool{
		"Sheriff": true, "Wrangler": true, "RangeHand": true, "Magistrate": true, "Bounty Hunter": true,
	}
	if !validRoles[req.GlobalRole] {
		http.Error(w, "Invalid role provided", http.StatusBadRequest)
		return
	}

	err = h.Store.UpdateUserRole(r.Context(), userID, req.GlobalRole)
	if err != nil {
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User role updated successfully to " + req.GlobalRole,
	})
}

// HandleDeactivateUser allows a Sheriff to safely offboard a user.
func (h *Handler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID in URL", http.StatusBadRequest)
		return
	}

	err = h.Store.DeactivateUserAndReassign(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to deactivate user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User successfully deactivated and tickets reassigned.",
	})
}

// CreateUserRequest is the payload the Sheriff sends to invite a new user
type CreateUserRequest struct {
	Email      string `json:"email"`
	FullName   string `json:"full_name"`
	Password   string `json:"password"`
	GlobalRole string `json:"global_role"`
}

// HandleCreateUser allows a Sheriff to manually provision a new user account.
func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.FullName == "" || req.Password == "" || req.GlobalRole == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validRoles := map[string]bool{
		"Sheriff": true, "Wrangler": true, "RangeHand": true, "Magistrate": true, "Bounty Hunter": true,
	}
	if !validRoles[req.GlobalRole] {
		http.Error(w, "Invalid role provided", http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Internal server error during hashing", http.StatusInternalServerError)
		return
	}

	user, err := h.Store.CreateUser(r.Context(), req.Email, req.FullName, hashedPassword, req.GlobalRole)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Email already exists in the system", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to provision user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "User provisioned successfully. Share the temporary password securely.",
		"id":          user.ID,
		"email":       user.Email,
		"full_name":   user.FullName,
		"global_role": user.GlobalRole,
	})
}

// HandleGetUsers returns a list of all users in the system for the Sheriff to manage.
func (h *Handler) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.Store.GetAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch user roster", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)
}
