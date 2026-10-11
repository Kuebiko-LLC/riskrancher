package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	domain2 "github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

func (h *Handler) HandleGetAdapters(w http.ResponseWriter, r *http.Request) {
	adapters, err := h.Store.GetAdapters(r.Context())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(adapters)
}

func (h *Handler) HandleCreateAdapter(w http.ResponseWriter, r *http.Request) {
	var adapter domain2.Adapter
	if err := json.NewDecoder(r.Body).Decode(&adapter); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := h.Store.SaveAdapter(r.Context(), adapter); err != nil {
		http.Error(w, "Failed to save adapter", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) HandleDeleteAdapter(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid adapter ID", http.StatusBadRequest)
		return
	}

	if err := h.Store.DeleteAdapter(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete adapter", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getJSONValue(data interface{}, path string) interface{} {
	if path == "" || path == "." {
		return data // The root IS the array
	}
	keys := strings.Split(path, ".")
	current := data
	for _, key := range keys {
		if m, ok := current.(map[string]interface{}); ok {
			current = m[key]
		} else {
			return nil // Path broke
		}
	}
	return current
}

func interfaceToString(val interface{}) string {
	if val == nil {
		return ""
	}
	if str, ok := val.(string); ok {
		return str
	}
	return "" // Could expand this to handle ints/floats if needed
}

// HandleAdapterIngest dynamically maps deeply nested JSON arrays into Tickets
func (h *Handler) HandleAdapterIngest(w http.ResponseWriter, r *http.Request) {
	adapterName := r.PathValue("name")
	adapter, err := h.Store.GetAdapterByName(r.Context(), adapterName)
	if err != nil {
		http.Error(w, "Adapter not found", http.StatusNotFound)
		return
	}

	var rawData interface{}
	if err := json.NewDecoder(r.Body).Decode(&rawData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	findingsNode := getJSONValue(rawData, adapter.FindingsPath)
	findingsArray, ok := findingsNode.([]interface{})
	if !ok {
		http.Error(w, "Findings path did not resolve to a JSON array", http.StatusBadRequest)
		return
	}

	type groupKey struct {
		Source string
		Asset  string
	}
	groupedTickets := make(map[groupKey][]domain2.Ticket)

	for _, item := range findingsArray {
		finding, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		ticket := domain2.Ticket{
			Source:                 adapter.SourceName,
			Status:                 "Waiting to be Triaged", // Explicitly set status
			Title:                  interfaceToString(finding[adapter.MappingTitle]),
			AssetIdentifier:        interfaceToString(finding[adapter.MappingAsset]),
			Severity:               interfaceToString(finding[adapter.MappingSeverity]),
			Description:            interfaceToString(finding[adapter.MappingDescription]),
			RecommendedRemediation: interfaceToString(finding[adapter.MappingRemediation]),
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
			log.Printf("🔥 JSON Ingestion Error for Asset %s: %v", key.Asset, err)
			// 🚀 LOG THE BATCH FAILURE
			h.Store.LogSync(r.Context(), key.Source, "Failed", len(batch), err.Error())
			http.Error(w, "Database error processing JSON batch", http.StatusInternalServerError)
			return
		} else {
			// 🚀 LOG THE SUCCESS
			h.Store.LogSync(r.Context(), key.Source, "Success", len(batch), "")
		}
	}

	w.WriteHeader(http.StatusCreated)
}
