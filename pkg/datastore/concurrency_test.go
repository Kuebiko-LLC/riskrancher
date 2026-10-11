package datastore

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// runChaosEngine fires 100 concurrent workers at the provided database connection
func runChaosEngine(db *sql.DB) int {
	db.Exec(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, status TEXT)`)
	db.Exec(`INSERT INTO tickets (title, status) VALUES ('Seed', 'Open')`)

	var wg sync.WaitGroup
	errCh := make(chan error, 1000)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			tx, _ := db.Begin()
			for j := 0; j < 50; j++ {
				tx.Exec(`INSERT INTO tickets (title, status) VALUES ('Vuln', 'Open')`)
			}
			if err := tx.Commit(); err != nil {
				errCh <- err
			}
		}
	}()

	for w := 0; w < 20; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := db.Exec(`UPDATE tickets SET status = 'Patched' WHERE id = 1`); err != nil {
					errCh <- err
				}
			}
		}()
	}

	for r := 0; r < 79; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				rows, err := db.Query(`SELECT COUNT(*) FROM tickets`)
				if err != nil {
					errCh <- err
				} else {
					rows.Close()
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	errorCount := 0
	for range errCh {
		errorCount++
	}
	return errorCount
}

func TestSQLiteConcurrency_Tuned_Succeeds(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "tuned.db")

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open tuned DB: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)

	errors := runChaosEngine(db)

	if errors > 0 {
		t.Fatalf("FAILED! Tuned engine threw %d errors. It should have queued them perfectly.", errors)
	}
	t.Log("SUCCESS: 100 concurrent workers survived SQLite chaos with ZERO locked errors.")
}
