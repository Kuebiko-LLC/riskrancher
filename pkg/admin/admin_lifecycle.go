package admin

import (
	"net/http"
	"time"
)

// HandleShutdown answers, then asks the server to stop a moment later so
// the response gets out. The binary is swapped by hand on an air-gapped
// box: stop it, copy the new file in, start it.
func (h *Handler) HandleShutdown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Stopping. Swap the binary and start it again."}`))
	go func() {
		time.Sleep(500 * time.Millisecond)
		if h.Shutdown != nil {
			h.Shutdown()
		}
	}()
}
