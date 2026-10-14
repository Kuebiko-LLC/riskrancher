package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

const TotalTickets = 10000   // Crank this to 1000000 for the ultimate stress test!
const TotalRiskRequests = 50 // Number of items for the Risk Reviews tab

func main() {
	db := datastore.InitDB("./data/riskrancher.db")
	defer db.Close()

	// Inject enterprise schema
	store := datastore.NewSQLiteStore(db)

	ctx := context.Background()

	// 1. Standard Triage Tickets
	stacks := []struct {
		Source   string
		Asset    string
		Title    string
		Desc     string
		Severity string
	}{
		{"Semgrep", "auth-api-repo", "Hardcoded JWT Secret", "Found a hardcoded secret in config.go.", "Critical"},
		{"Trivy", "frontend-image:latest", "CVE-2024-1234 in OpenSSL", "Container image contains vulnerable library.", "High"},
		{"Prowler", "aws-prod-account", "S3 Bucket Public Access", "Bucket 'company-data' has no public access block.", "Critical"},
		{"DefectDojo", "payment-service", "Outdated Log4j", "SCA detected Log4j 2.14. Upgrade immediately.", "High"},
		{"OWASP ZAP", "https://api.ranch.com", "Blind SQL Injection", "DAST scan detected a boolean-based blind SQLi payload success.", "Critical"},
		{"Falco", "k8s-cluster-prod", "Unexpected Shell Execution", "A shell was spawned inside the api-pod container at runtime.", "Critical"},
		{"SonarQube", "legacy-crm-repo", "Code Smell: Cognitive Complexity", "Function exceeds complexity threshold.", "Low"},
	}

	log.Printf("🌱 Seeding the database with %d standard tickets...", TotalTickets)
	start := time.Now()
	successCount := 0

	for i := 1; i <= TotalTickets; i++ {
		profile := stacks[rand.Intn(len(stacks))]

		ticket := &domain.Ticket{
			Source:             profile.Source,
			AssetIdentifier:    profile.Asset,
			Title:              fmt.Sprintf("%s (Variant %d)", profile.Title, rand.Intn(1000)),
			Description:        profile.Desc,
			Severity:           profile.Severity,
			Status:             "Waiting to be Triaged",
			DedupeHash:         fmt.Sprintf("hash-%d-%s", i, profile.Asset),
			TriageDueDate:      time.Now().Add(24 * time.Hour),
			RemediationDueDate: time.Now().Add(7 * 24 * time.Hour),
		}

		if err := store.CreateTicket(ctx, ticket); err == nil {
			successCount++
		}
	}

	// 2. Risk Review Tickets (Pending Risk Approval)
	riskStacks := []struct {
		Source   string
		Asset    string
		Title    string
		Desc     string
		Severity string
	}{
		{"Manual Request", "legacy-billing-db", "Cannot upgrade to TLS 1.2", "System is hardcoded to use old cipher suites. Requires 6-month refactor. Requesting 180 day exception.", "High"},
		{"Vendor Exception", "vendor-portal", "Unpatched Struts2 Vulnerability", "Vendor is out of business. Working on migration. Need 90 day exception.", "Critical"},
		{"IT Ops", "dev-k8s-cluster", "Admin exposed to 0.0.0.0", "Temporary exception needed for contractor access during the weekend migration window.", "High"},
		{"False Positive", "auth-api-repo", "Misidentified Secret", "The 'secret' found by Semgrep is actually a public test key used for unit tests. Requesting permanent suppression.", "Critical"},
	}

	log.Printf("⚖️ Seeding %d Risk Review Requests...", TotalRiskRequests)
	riskSuccessCount := 0

	for i := 1; i <= TotalRiskRequests; i++ {
		profile := riskStacks[rand.Intn(len(riskStacks))]

		ticket := &domain.Ticket{
			Source:             profile.Source,
			AssetIdentifier:    profile.Asset,
			Title:              fmt.Sprintf("[RISK EXCEPTION] %s (ID: %d)", profile.Title, rand.Intn(9999)),
			Description:        profile.Desc,
			Severity:           profile.Severity,
			Status:             "Pending Risk Approval", // <--- THIS MAKES IT SHOW UP IN THE TAB
			DedupeHash:         fmt.Sprintf("risk-hash-%d-%s", i, profile.Asset),
			TriageDueDate:      time.Now().Add(24 * time.Hour),
			RemediationDueDate: time.Now().Add(7 * 24 * time.Hour),
		}

		if err := store.CreateTicket(ctx, ticket); err == nil {
			riskSuccessCount++
		}
	}

	duration := time.Since(start)
	log.Printf("✅ Seeding complete! Inserted %d standard tickets and %d risk requests in %v", successCount, riskSuccessCount, duration)
}
