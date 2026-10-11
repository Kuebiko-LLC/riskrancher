package admin

import (
	"log"
	"net/http"
)

// maxFindingsPerRequest caps how many finding ids a single request may carry
// (report generation/edit, engagement add-findings), to bound work per call.
const maxFindingsPerRequest = 2000

var validSeverities = map[string]bool{
	"Critical": true, "High": true, "Medium": true, "Low": true, "Informational": true,
}

func validSeverity(s string) bool { return validSeverities[s] }

// httpServerError logs the real error server-side and returns a generic message,
// so internal (SQL/schema) detail never reaches the client.
func httpServerError(w http.ResponseWriter, where string, err error) {
	log.Printf("%s: %v", where, err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
