package models

import "time"

// Engagement is one penetration test: a container, owned by a Bounty Hunter,
// that groups the findings discovered during that test. Findings link back to
// it via tickets.engagement_id.
type Engagement struct {
	ID         int       `json:"id"`
	Number     string    `json:"number"` // auto-assigned, e.g. ENG-0001
	Name       string    `json:"name"`
	Client     string    `json:"client"`
	OwnerEmail string    `json:"owner_email"` // the Bounty Hunter running it
	Status     string    `json:"status"`      // Active | Released | Closed
	CreatedAt  time.Time `json:"created_at"`
}
