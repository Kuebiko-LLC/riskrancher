package sla

import (
	"context"
	"log"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// DefaultSLACalculator implements the SLACalculator interface
type DefaultSLACalculator struct {
	Timezone      string
	BusinessStart int
	BusinessEnd   int
	Holidays      map[string]bool
}

// NewSLACalculator returns the interface
func NewSLACalculator() domain.SLACalculator {
	return &DefaultSLACalculator{
		Timezone:      "UTC",
		BusinessStart: 9,
		BusinessEnd:   17,
		Holidays:      make(map[string]bool),
	}
}

// CalculateDueDate for the finding based on SLA
func (c *DefaultSLACalculator) CalculateDueDate(severity string) *time.Time {
	var days int
	switch severity {
	case "Critical":
		days = 3
	case "High":
		days = 14
	case "Medium":
		days = 30
	case "Low":
		days = 90
	default:
		days = 30
	}

	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		log.Printf("Warning: Invalid timezone '%s', falling back to UTC", c.Timezone)
		loc = time.UTC
	}

	nowLocal := time.Now().In(loc)
	dueDate := c.AddBusinessDays(nowLocal, days)
	return &dueDate
}

// AddBusinessDays for working days not weekends and some holidays
func (c *DefaultSLACalculator) AddBusinessDays(start time.Time, businessDays int) time.Time {
	current := start
	added := 0
	for added < businessDays {
		current = current.AddDate(0, 0, 1)
		weekday := current.Weekday()
		dateStr := current.Format("2006-01-02")
		if weekday != time.Saturday && weekday != time.Sunday && !c.Holidays[dateStr] {
			added++
		}
	}
	return current
}

// CalculateTrueSLAHours based on the time of action for ticket
func (c *DefaultSLACalculator) CalculateTrueSLAHours(ctx context.Context, ticketID int, store domain.Store) (float64, error) {
	appConfig, err := store.GetAppConfig(ctx)
	if err != nil {
		return 0, err
	}

	ticket, err := store.GetTicketByID(ctx, ticketID)
	if err != nil {
		return 0, err
	}

	end := time.Now()
	if ticket.PatchedAt != nil {
		end = *ticket.PatchedAt
	}

	totalActiveBusinessHours := c.calculateBusinessHoursBetween(ticket.CreatedAt, end, appConfig)
	return totalActiveBusinessHours, nil
}

// calculateBusinessHoursBetween calculates strict working hours between two timestamps
func (c *DefaultSLACalculator) calculateBusinessHoursBetween(start, end time.Time, config domain.AppConfig) float64 {
	loc, _ := time.LoadLocation(config.Timezone)
	start = start.In(loc)
	end = end.In(loc)

	if start.After(end) {
		return 0
	}

	var activeHours float64
	current := start

	for current.Before(end) {
		nextHour := current.Add(time.Hour)
		if nextHour.After(end) {
			nextHour = end
		}

		weekday := current.Weekday()
		dateStr := current.Format("2006-01-02")
		hour := current.Hour()

		isWeekend := weekday == time.Saturday || weekday == time.Sunday
		isHoliday := c.Holidays[dateStr]
		isBusinessHour := hour >= config.BusinessStart && hour < config.BusinessEnd

		if !isWeekend && !isHoliday && isBusinessHour {
			activeHours += nextHour.Sub(current).Hours()
		}

		current = nextHour
	}

	return activeHours
}
