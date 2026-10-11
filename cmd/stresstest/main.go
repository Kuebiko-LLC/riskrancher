package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/auth"
	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
)

func main() {
	sizeFlag := flag.String("size", "small", "Choose 'small' (100 tickets) or 'large' (300,000 tickets)")
	flag.Parse()

	totalTickets := 100
	batchSize := 100

	if *sizeFlag == "large" {
		totalTickets = 300000
		batchSize = 10000 // Ingest in chunks of 10k
	}

	db := datastore.InitDB("./data/RiskRancher.db")
	defer db.Close()

	log.Printf("🧹 Sweeping the ranch (Deleting old test data)...")

	db.Exec("DELETE FROM ticket_assignments")
	db.Exec("DELETE FROM tickets")
	db.Exec("DELETE FROM sync_logs")
	db.Exec("DELETE FROM draft_tickets")

	// Reset the auto-increment counters so Ticket IDs reliably start at 1
	db.Exec("DELETE FROM sqlite_sequence")

	log.Println("⚙️ Seeding global config, adapters, and SLA matrix...")

	db.Exec("INSERT OR IGNORE INTO app_config (id, timezone, business_start, business_end, default_extension_days) VALUES (1, 'America/New_York', 9, 17, 30)")
	db.Exec("INSERT OR IGNORE INTO domains (name) VALUES ('Vulnerability'), ('Privacy'), ('Compliance'), ('Incident')")
	db.Exec("INSERT OR IGNORE INTO departments (name) VALUES ('Security'), ('IT'), ('Privacy'), ('Legal'), ('Compliance')")

	slaQuery := `INSERT OR IGNORE INTO sla_policies (domain, severity, days_to_triage, days_to_remediate, max_extensions) VALUES
       ('Vulnerability', 'Critical', 1, 3, 0), ('Vulnerability', 'High', 3, 14, 1), ('Vulnerability', 'Medium', 5, 30, 2), ('Vulnerability', 'Low', 8, 90, 3), ('Vulnerability', 'Info', 0, 0, 0)`
	db.Exec(slaQuery)

	adapterQuery := `INSERT OR IGNORE INTO data_adapters (name, source_name, findings_path, mapping_title, mapping_asset, mapping_severity) VALUES
       ('Trivy Container Security', 'Trivy', '.', 'title', 'asset', 'severity'),
       ('GitHub Dependabot', 'Dependabot', '.', 'title', 'asset', 'severity'),
       ('Tenable Nessus', 'Nessus', '.', 'title', 'asset', 'severity'),
       ('Manual Entry API', 'Manual', '.', 'title', 'asset', 'severity')`
	db.Exec(adapterQuery)

	validHash, _ := auth.HashPassword("password123")

	_, err := db.Exec("INSERT OR REPLACE INTO users (id, email, full_name, password_hash, global_role, is_active) VALUES (999, 'stress@ranch.com', 'Stress Tester', ?, 'Sheriff', 1)", validHash)
	if err != nil {
		log.Fatalf("🚨 Failed to seed Stress User (Database locked?): %v", err)
	}

	_, err = db.Exec("INSERT OR REPLACE INTO sessions (session_token, user_id, expires_at) VALUES ('stress_token_123', 999, datetime('now', '+1 hour'))")
	if err != nil {
		log.Fatalf("🚨 Failed to seed Stress Session: %v", err)
	}

	log.Println("==========================================================================")
	log.Printf("🚀 COMMENCING %d TICKET API LOAD TEST (%s mode)", totalTickets, *sizeFlag)
	log.Println("⚠️  CRITICAL: Ensure your RiskRancher server is running in another terminal!")
	log.Println("==========================================================================")
	time.Sleep(1 * time.Second)

	client := &http.Client{Timeout: 5 * time.Minute}
	baseURL := "http://localhost:8080"
	sessionCookie := &http.Cookie{Name: "session_token", Value: "stress_token_123"}

	ticketCounter := 1

	log.Printf("📥 PHASE 1: Ingesting via API in batches of %d...", batchSize)
	for b := 0; b < totalTickets/batchSize; b++ {
		var payload []map[string]string

		for i := 0; i < batchSize; i++ {
			assetName := fmt.Sprintf("server-prod-%05d", (ticketCounter%50)+1)

			sev := "Medium"
			if ticketCounter%10 == 0 {
				sev = "Critical"
			} else if ticketCounter%5 == 0 {
				sev = "High"
			} else if ticketCounter%2 == 0 {
				sev = "Low"
			}

			source := "Trivy"
			if ticketCounter%3 == 0 {
				source = "Dependabot"
			} else if ticketCounter%7 == 0 {
				source = "Nessus"
			}

			payload = append(payload, map[string]string{
				"source":           source,
				"asset_identifier": assetName,
				"title":            fmt.Sprintf("Vulnerability-%06d", ticketCounter),
				"severity":         sev,
				"description":      fmt.Sprintf("Stress test vulnerability payload #%d", ticketCounter),
			})
			ticketCounter++
		}

		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/ingest", bytes.NewBuffer(body))
		req.AddCookie(sessionCookie)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("🚨 API Request failed: %v", err)
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			log.Fatalf("🚨 API returned unexpected status: %d", resp.StatusCode)
		}
		resp.Body.Close()
		fmt.Printf("✅ Ingested batch %d/%d (%d tickets)\n", b+1, totalTickets/batchSize, len(payload))
	}

	log.Println("\n🔀 PHASE 2: Distributing tickets to valid Core workflows...")

	unassignedEnd := int(float64(totalTickets) * 0.60) // 60% stay in Holding Pen
	assignedEnd := int(float64(totalTickets) * 0.75)   // 15% go to Chute
	returnedEnd := int(float64(totalTickets) * 0.85)   // 10% Returned to Security
	falsePosEnd := int(float64(totalTickets) * 0.90)   // 5% False Positive
	patchedEnd := totalTickets                         // 10% Patched

	log.Printf("⏳ Keeping Tickets 1 - %d in the Holding Pen (Unassigned)...", unassignedEnd)
	bulkUpdateDB(db, unassignedEnd+1, assignedEnd, "Assigned Out", "it-network@ranch.com")
	bulkUpdateDB(db, assignedEnd+1, returnedEnd, "Returned to Security", "it-endpoint@ranch.com")
	bulkUpdateDB(db, returnedEnd+1, falsePosEnd, "False Positive", "security@ranch.com")
	bulkUpdateDB(db, falsePosEnd+1, patchedEnd, "Patched", "it-network@ranch.com")

	log.Println("\n🎉 STRESS TEST COMPLETE!")
	log.Println("==========================================================================")
	log.Println("🤠 The ranch is fully loaded with Core data. Go check the Dashboard!")
	log.Println("🔑 Login -> Email: stress@ranch.com | Password: password123")
	log.Println("==========================================================================")
}

// bulkUpdateDB executes direct SQLite updates
func bulkUpdateDB(db *sql.DB, startID, endID int, status, assignee string) {
	if startID > endID {
		return
	}
	fmt.Printf("Moving %d tickets (%d to %d) -> %s...\n", (endID-startID)+1, startID, endID, status)

	query := `UPDATE tickets SET status = ?, assignee = ?, latest_comment = 'Stress test auto-distribution', updated_at = CURRENT_TIMESTAMP WHERE id >= ? AND id <= ?`

	_, err := db.Exec(query, status, assignee, startID, endID)
	if err != nil {
		log.Fatalf("🚨 DB update failed: %v", err)
	}
}
