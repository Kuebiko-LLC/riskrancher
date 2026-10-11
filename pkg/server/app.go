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
}

type FreeAuth struct{}

func (f *FreeAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In the OSS version, we just pass the request to the next handler for now.
		next.ServeHTTP(w, r)
	})
}

// NewApp creates a  Risk Rancher Core application with OSS defaults.
func NewApp(store domain.Store) *App {
	return &App{
		Store:  store,
		Router: http.NewServeMux(),
		Auth:   &FreeAuth{},
		SLA:    sla.NewSLACalculator(),
	}
}
