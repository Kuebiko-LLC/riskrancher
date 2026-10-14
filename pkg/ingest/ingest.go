package ingest

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (h *Handler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	h.Store.ReopenExpiredExceptions(r.Context())
	decoder := json.NewDecoder(r.Body)
	_, err := decoder.Token()
	if err != nil {
		http.Error(w, "Invalid JSON payload: expected array", http.StatusBadRequest)
		return
	}

	type groupKey struct {
		Source string
		Asset  string
	}
	groupedTickets := make(map[groupKey][]domain.Ticket)
	for decoder.More() {
		var ticket domain.Ticket
		if err := decoder.Decode(&ticket); err != nil {
			http.Error(w, "Error parsing ticket object", http.StatusBadRequest)
			return
		}

		if ticket.Status == "" {
			ticket.Status = "Waiting to be Triaged"
		}

		if ticket.DedupeHash == "" {
			hashInput := ticket.Source + "|" + ticket.AssetIdentifier + "|" + ticket.Title
			hash := sha256.Sum256([]byte(hashInput))
			ticket.DedupeHash = hex.EncodeToString(hash[:])
		}

		key := groupKey{
			Source: ticket.Source,
			Asset:  ticket.AssetIdentifier,
		}
		groupedTickets[key] = append(groupedTickets[key], ticket)
	}

	_, err = decoder.Token()
	if err != nil {
		http.Error(w, "Invalid JSON payload termination", http.StatusBadRequest)
		return
	}

	for key, batch := range groupedTickets {
		err := h.Store.ProcessIngestionBatch(r.Context(), key.Source, key.Asset, batch)
		if err != nil {
			log.Printf("🔥 Ingestion DB Error for Asset %s: %v", key.Asset, err)
			h.Store.LogSync(r.Context(), key.Source, "Failed", len(batch), err.Error())
			http.Error(w, "Database error processing batch", http.StatusInternalServerError)
			return
		} else {
			h.Store.LogSync(r.Context(), key.Source, "Success", len(batch), "")
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) HandleCSVIngest(w http.ResponseWriter, r *http.Request) {
	h.Store.ReopenExpiredExceptions(r.Context())
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	var adapter domain.Adapter
	var err error

	// Prefer adapter_name (UI); fall back to adapter_id for tests/API clients
	if adapterName := r.FormValue("adapter_name"); adapterName != "" {
		adapter, err = h.Store.GetAdapterByName(r.Context(), adapterName)
		if err != nil {
			http.Error(w, "Adapter mapping not found", http.StatusNotFound)
			return
		}
	} else if idStr := r.FormValue("adapter_id"); idStr != "" {
		var id int
		if _, scanErr := fmt.Sscanf(idStr, "%d", &id); scanErr != nil || id < 1 {
			http.Error(w, "Invalid adapter_id", http.StatusBadRequest)
			return
		}
		adapter, err = h.Store.GetAdapterByID(r.Context(), id)
		if err != nil {
			http.Error(w, "Adapter mapping not found", http.StatusNotFound)
			return
		}
	} else {
		http.Error(w, "Missing adapter_name or adapter_id", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file payload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		http.Error(w, "Invalid or empty CSV format", http.StatusBadRequest)
		return
	}

	headers := records[0]
	headerMap := make(map[string]int)
	for i, h := range headers {
		headerMap[h] = i
	}

	type groupKey struct {
		Source string
		Asset  string
	}
	groupedTickets := make(map[groupKey][]domain.Ticket)

	for _, row := range records[1:] {
		ticket := domain.Ticket{
			Source: adapter.SourceName,
			Status: "Waiting to be Triaged",
		}

		if idx, ok := headerMap[adapter.MappingTitle]; ok && idx < len(row) {
			ticket.Title = row[idx]
		}
		if idx, ok := headerMap[adapter.MappingAsset]; ok && idx < len(row) {
			ticket.AssetIdentifier = row[idx]
		}
		if idx, ok := headerMap[adapter.MappingSeverity]; ok && idx < len(row) {
			ticket.Severity = row[idx]
		}
		if idx, ok := headerMap[adapter.MappingDescription]; ok && idx < len(row) {
			ticket.Description = row[idx]
		}
		if adapter.MappingRemediation != "" {
			if idx, ok := headerMap[adapter.MappingRemediation]; ok && idx < len(row) {
				ticket.RecommendedRemediation = row[idx]
			}
		}

		if ticket.Title != "" && ticket.AssetIdentifier != "" {
			hashInput := ticket.Source + "|" + ticket.AssetIdentifier + "|" + ticket.Title
			hash := sha256.Sum256([]byte(hashInput))
			ticket.DedupeHash = hex.EncodeToString(hash[:])
			key := groupKey{Source: ticket.Source, Asset: ticket.AssetIdentifier}
			groupedTickets[key] = append(groupedTickets[key], ticket)
		}
	}

	for key, batch := range groupedTickets {
		err := h.Store.ProcessIngestionBatch(r.Context(), key.Source, key.Asset, batch)
		if err != nil {
			log.Printf("🔥 CSV Ingestion Error for Asset %s: %v", key.Asset, err)
			h.Store.LogSync(r.Context(), key.Source, "Failed", len(batch), err.Error())
			http.Error(w, "Database error processing CSV batch", http.StatusInternalServerError)
			return
		} else {
			h.Store.LogSync(r.Context(), key.Source, "Success", len(batch), "")
		}
	}
	w.WriteHeader(http.StatusCreated)
}
