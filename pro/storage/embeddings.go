package storage

import (
	"bytes"
	"context"
	"encoding/binary"
)

// SaveTicketEmbedding saves the float32 array AND the asset boundary
func (s *ProSQLiteStore) SaveTicketEmbedding(ctx context.Context, ticketID int, assetIdentifier string, embedding []float32) error {
	// Note: no loop needed; binary.Write can serialize the entire slice at once.
	// This is significantly faster and prevents memory fragmentation.
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, embedding); err != nil {
		return err
	}

	// 🤠 FIX: Never combine CREATE TABLE and INSERT in a parameterized query in Go.
	// We rely on pro_schema.sql to build the table, and only execute the INSERT here.
	query := `INSERT OR REPLACE INTO pro_ticket_embeddings (ticket_id, asset_identifier, embedding) VALUES (?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query, ticketID, assetIdentifier, buf.Bytes())
	return err
}

// FetchEmbeddingsByAsset pulls known vectors ONLY for the targeted asset
func (s *ProSQLiteStore) FetchEmbeddingsByAsset(ctx context.Context, assetIdentifier string) (map[int][]float32, error) {
	query := `SELECT ticket_id, embedding FROM pro_ticket_embeddings WHERE asset_identifier = ?`
	rows, err := s.db.QueryContext(ctx, query, assetIdentifier)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[int][]float32)
	for rows.Next() {
		var id int
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			continue
		}

		embedding := make([]float32, len(blob)/4)
		buf := bytes.NewReader(blob)
		// 🤠 FIX: Remove the '&'. Pass the slice directly so binary.Read fills the elements.
		if err := binary.Read(buf, binary.LittleEndian, embedding); err == nil {
			results[id] = embedding
		}
	}
	return results, nil
}
