package admin

import (
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Handler encapsulates all Admin and Sheriff HTTP logic
type Handler struct {
	Store domain.Store
	// Shutdown stops the server; wired by the server package.
	Shutdown func()
}

// NewHandler creates a new Admin Handler
func NewHandler(store domain.Store) *Handler {
	return &Handler{Store: store}
}
