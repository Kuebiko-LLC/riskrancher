package models

import "time"

// Evidence is a processed screenshot/image attached to a finding. The image
// bytes (web + thumbnail) live in the store, not on this struct, so metadata
// can be listed cheaply without loading blobs.
type Evidence struct {
	ID          int       `json:"id"`
	TicketID    int       `json:"ticket_id"`
	Caption     string    `json:"caption"`
	ContentType string    `json:"content_type"`
	Width       int       `json:"width"`
	Height      int       `json:"height"`
	Size        int       `json:"size"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}
