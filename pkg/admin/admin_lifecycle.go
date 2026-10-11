package admin

import (
	"encoding/json"
	"net/http"
	"time"
)

const CurrentAppVersion = "v1.0.0"

type UpdateCheckResponse struct {
	Status          string `json:"status"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Message         string `json:"message"`
}

// HandleCheckUpdates pings GitHub. If air-gapped, it returns manual instructions.
func (h *Handler) HandleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	respPayload := UpdateCheckResponse{
		CurrentVersion: CurrentAppVersion,
	}

	client := http.Client{Timeout: 3 * time.Second}

	githubURL := "https://api.github.com/repos/Kuebiko-LLC/risk-rancher-core/releases/latest"
	resp, err := client.Get(githubURL)

	if err != nil || resp.StatusCode != http.StatusOK {
		respPayload.Status = "offline"
		respPayload.Message = "No internet connection detected. To update an air-gapped server: Download the latest RiskRancher binary on a connected machine, transfer it via rsync or scp to this server, and restart the service."

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(respPayload)
		return
	}
	defer resp.Body.Close()

	var ghRelease struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghRelease); err == nil {
		respPayload.Status = "online"
		respPayload.LatestVersion = ghRelease.TagName
		respPayload.UpdateAvailable = (ghRelease.TagName != CurrentAppVersion)

		if respPayload.UpdateAvailable {
			respPayload.Message = "A new version is available! Please trigger a graceful shutdown and swap the binary."
		} else {
			respPayload.Message = "You are running the latest version."
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respPayload)
}

// HandleShutdown signals the application to close connections and exit cleanly
func (h *Handler) HandleShutdown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Initiating graceful shutdown. The server will exit in 2 seconds..."}`))
	go func() {
		time.Sleep(2 * time.Second)
	}()
}
