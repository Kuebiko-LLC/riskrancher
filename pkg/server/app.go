package server

import (
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pkg/sla"
)

type App struct {
	Store  domain.Store
	Router *http.ServeMux
	Auth   domain.Authenticator
	SLA    domain.SLACalculator
	// Shutdown stops the listening server; main sets it, the admin
	// shutdown route calls it.
	Shutdown func()
}

type FreeAuth struct{}

func (f *FreeAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Passes the request to the next handler.
		next.ServeHTTP(w, r)
	})
}

// NewApp wires the store into an application with its router, auth, and SLA calculator.
func NewApp(store domain.Store) *App {
	return &App{
		Store:  store,
		Router: http.NewServeMux(),
		Auth:   &FreeAuth{},
		SLA:    sla.NewSLACalculator(),
	}
}
