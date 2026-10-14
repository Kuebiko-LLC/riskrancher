package server

import (
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// App is the store and the router, plus the hook that stops the server.
type App struct {
	Store  domain.Store
	Router *http.ServeMux
	// Shutdown stops the listening server; main sets it, the admin
	// shutdown route calls it.
	Shutdown func()
}

// NewApp wires the store into an application with its router.
func NewApp(store domain.Store) *App {
	return &App{
		Store:  store,
		Router: http.NewServeMux(),
	}
}
