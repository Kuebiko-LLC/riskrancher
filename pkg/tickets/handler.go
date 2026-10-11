package tickets

import (
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// Handler encapsulates all Ticket-related HTTP logic
type Handler struct {
	Store domain.Store
}

// NewHandler creates a new Tickets Handler
func NewHandler(store domain.Store) *Handler {
	return &Handler{Store: store}
}
