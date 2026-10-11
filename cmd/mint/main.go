// Command mint seeds a local QA environment: a spread of tickets across every
// dashboard tab plus working magic-link batches for the Wrangler and Magistrate
// portals. Development tool only; it wipes the ticket tables first.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	core "github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/storage"
)

func main() {
	log.Println("🤠 Saddle up! Preparing the RiskRancher QA Environment...")

	db := core.InitDB("./data/riskrancher.db")
	defer db.Close()

	// Wipe existing data for a clean QA run
	db.Exec("DELETE FROM ticket_activity")
	db.Exec("DELETE FROM tickets")
	db.Exec("DELETE FROM magic_batches")
	db.Exec("DELETE FROM sqlite_sequence") // Reset auto-increment IDs

	// Inject enterprise schema
	storage.InjectProSchema(db)
	store := storage.NewProSQLiteStore(db)

	ctx := context.Background()
	now := time.Now()

	// ==========================================
	// 1. THE HOLDING PEN (Analyst View)
	// ==========================================
	log.Println("📩 Seeding Holding Pen (Unassigned Tickets)...")
	for i := 1; i <= 15; i++ {
		store.CreateTicket(ctx, &domain.Ticket{
			Source:             "Trivy",
			AssetIdentifier:    "frontend-api-prod",
			Title:              fmt.Sprintf("Holding Pen Vuln %d (CVE-2024-%04d)", i, i),
			Description:        "Needs to be reviewed by an analyst and assigned out.",
			Severity:           "High",
			Status:             "Waiting to be Triaged",
			TriageDueDate:      now.Add(24 * time.Hour),
			RemediationDueDate: now.Add(14 * 24 * time.Hour),
		})
	}

	// ==========================================
	// 2. THE CHUTE / RANGEHAND (Wrangler/IT View)
	// ==========================================
	log.Println("🤠 Seeding The Chute (Wrangler/IT Inbox)...")
	wranglerToken := "qa-wrangler-magic-token-777"
	var wranglerIDs []int
	for i := 1; i <= 10; i++ {
		ticket := &domain.Ticket{
			Source:             "Semgrep",
			AssetIdentifier:    "payment-gateway-repo",
			Title:              fmt.Sprintf("Hardcoded Secret %d", i),
			Description:        "IT needs to review this and either fix it, or request a risk exception.",
			Severity:           "Critical",
			Status:             "Assigned Out",
			Assignee:           "it-ops@ranch.com",
			TriageDueDate:      now.Add(-24 * time.Hour), // Overdue for triage!
			RemediationDueDate: now.Add(7 * 24 * time.Hour),
		}
		store.CreateTicket(ctx, ticket)
		wranglerIDs = append(wranglerIDs, ticket.ID)
	}
	seedMagicBatch(ctx, db, wranglerToken, "it-ops@ranch.com", wranglerIDs)

	// ==========================================
	// 3. PENDING VERIFICATION (Analyst Review)
	// ==========================================
	log.Println("👀 Seeding Pending Verification (IT claims it's fixed)...")
	for i := 1; i <= 5; i++ {
		store.CreateTicket(ctx, &domain.Ticket{
			Source:             "Prowler",
			AssetIdentifier:    "aws-prod-account",
			Title:              fmt.Sprintf("S3 Public Bucket %d", i),
			Description:        "IT marked this as fixed. Security needs to verify the evidence.",
			Severity:           "Critical",
			Status:             "Pending Verification",
			Assignee:           "cloud-team@ranch.com",
			TriageDueDate:      now,
			RemediationDueDate: now.Add(2 * 24 * time.Hour),
		})
	}

	// ==========================================
	// 4. MAGISTRATE / RISK REVIEWS (Legal/Exec View)
	// ==========================================
	log.Println("⚖️ Seeding Risk Reviews (Magistrate Exceptions)...")
	magistrateToken := "qa-magistrate-magic-token-999"
	var magistrateIDs []int
	for i := 1; i <= 8; i++ {
		ticket := &domain.Ticket{
			Source:             "Nessus",
			AssetIdentifier:    "legacy-mainframe",
			Title:              fmt.Sprintf("Unsupported OS Version %d", i),
			Description:        "IT requested an exception because they cannot upgrade this machine. \n\n**IT Justification:** We don't have the budget until Q4.",
			Severity:           "High",
			Status:             "Pending Risk Approval",
			Assignee:           "legacy-it@ranch.com",
			TriageDueDate:      now,
			RemediationDueDate: now.Add(30 * 24 * time.Hour),
		}
		// Some have been viewed, some haven't (Tests the bold/unread UI)
		if i%2 == 0 {
			nowTime := now
			ticket.OwnerViewedAt = &nowTime
		}
		store.CreateTicket(ctx, ticket)
		magistrateIDs = append(magistrateIDs, ticket.ID)
	}
	seedMagicBatch(ctx, db, magistrateToken, "legacy-it@ranch.com", magistrateIDs)

	// ==========================================
	// 5. THE ARCHIVES (Patched / False Positives)
	// ==========================================
	log.Println("🗄️ Seeding The Archives...")
	for i := 1; i <= 10; i++ {
		status := "Patched"
		if i%3 == 0 {
			status = "False Positive"
		} else if i%5 == 0 {
			status = "Risk Accepted"
		}

		store.CreateTicket(ctx, &domain.Ticket{
			Source:             "SonarQube",
			AssetIdentifier:    "api-v1",
			Title:              fmt.Sprintf("Archived Finding %d", i),
			Description:        "This ticket is closed and should only appear in the archives.",
			Severity:           "Medium",
			Status:             status,
			Assignee:           "dev@ranch.com",
			TriageDueDate:      now,
			RemediationDueDate: now,
		})
	}

	// ==========================================
	// 🤠 QA SUMMARY OUTPUT
	// ==========================================
	fmt.Println("\n================================================================")
	fmt.Println("✅ QA ENVIRONMENT SUCCESSFULLY SEEDED!")
	fmt.Println("================================================================")
	fmt.Println("You can now test all 3 major portals immediately:")
	fmt.Println()
	fmt.Println("🛡️  1. ANALYST PORTAL (The Dashboard)")
	fmt.Println("   URL: http://localhost:8080/dashboard")
	fmt.Println("   - Check the 'Holding Pen' for raw tickets.")
	fmt.Println("   - Check 'Pending Verification' to accept/reject IT's fixes.")
	fmt.Println()
	fmt.Println("🤠 2. WRANGLER PORTAL (The IT/Developer View)")
	fmt.Println("   URL: http://localhost:8080/share/" + wranglerToken)
	fmt.Println("   - This is what IT sees when you assign them tickets.")
	fmt.Println("   - Try submitting a fix, or requesting a risk exception.")
	fmt.Println()
	fmt.Println("⚖️  3. MAGISTRATE PORTAL (The Executive/Risk View)")
	fmt.Println("   URL: http://localhost:8080/review/" + magistrateToken)
	fmt.Println("   - This is what Legal/Execs see when IT asks for an exception.")
	fmt.Println("   - Try Approving or Denying the risk requests.")
	fmt.Println("================================================================")
}

// seedMagicBatch wires a static magic-link token to a set of tickets so the
// /share and /review portals resolve during QA. Mirrors the magic_batches row
// that BulkUpdateStatusAndAssign writes in production.
func seedMagicBatch(ctx context.Context, db *sql.DB, token, createdBy string, ticketIDs []int) {
	if len(ticketIDs) == 0 {
		return
	}
	idsJSON, _ := json.Marshal(ticketIDs)
	_, err := db.ExecContext(ctx, `
		INSERT INTO magic_batches (token, created_by, expires_at, ticket_ids)
		VALUES (?, ?, DATETIME('now', '+90 days'), ?)`,
		token, createdBy, string(idsJSON))
	if err != nil {
		log.Printf("⚠️ could not seed magic batch %q: %v", token, err)
	}
}
