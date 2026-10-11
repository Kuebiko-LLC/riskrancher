package ingest

import (
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

type Handler struct {
	Store domain.Store
}

func NewHandler(store domain.Store) *Handler {
	return &Handler{Store: store}
}
