package models

import "time"

// PentestReport is a generated engagement deliverable: a frozen snapshot of a
// set of findings (tickets) rendered into Markdown and HTML at creation time.
type PentestReport struct {
	ID               int       `json:"id"`
	Title            string    `json:"title"`
	ClientName       string    `json:"client_name"`
	Author           string    `json:"author"`
	Scope            string    `json:"scope"`
	ExecutiveSummary string    `json:"executive_summary"`
	TicketIDs        []int     `json:"ticket_ids"`
	Markdown         string    `json:"markdown,omitempty"`
	HTML             string    `json:"html,omitempty"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
}
