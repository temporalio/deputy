package explain

import (
	"fmt"
	"time"
)

// TemporalInfo contains time-based analysis of a vulnerability.
type TemporalInfo struct {
	// Published is when the vulnerability was first disclosed.
	Published time.Time
	// Modified is when the vulnerability was last updated.
	Modified time.Time
	// KEVAdded is when CISA added this to the KEV catalog (if applicable).
	KEVAdded time.Time
	// KEVDueDate is the federal remediation deadline (if applicable).
	KEVDueDate time.Time
}

// Age returns the time since the vulnerability was published.
func (t TemporalInfo) Age() time.Duration {
	if t.Published.IsZero() {
		return 0
	}
	return time.Since(t.Published)
}

// DaysSincePublished returns the number of days since publication.
func (t TemporalInfo) DaysSincePublished() int {
	if t.Published.IsZero() {
		return 0
	}
	return int(time.Since(t.Published).Hours() / 24)
}

// TimeSinceModified returns the duration since last modification.
func (t TemporalInfo) TimeSinceModified() time.Duration {
	if t.Modified.IsZero() {
		return 0
	}
	return time.Since(t.Modified)
}

// KEVTimeInCatalog returns how long the CVE has been in KEV.
func (t TemporalInfo) KEVTimeInCatalog() time.Duration {
	if t.KEVAdded.IsZero() {
		return 0
	}
	return time.Since(t.KEVAdded)
}

// KEVDaysOverdue returns how many days past the KEV due date we are.
// Returns 0 if not overdue or no due date.
func (t TemporalInfo) KEVDaysOverdue() int {
	if t.KEVDueDate.IsZero() {
		return 0
	}
	if time.Now().Before(t.KEVDueDate) {
		return 0
	}
	return int(time.Since(t.KEVDueDate).Hours() / 24)
}

// KEVDaysRemaining returns how many days until the KEV due date.
// Returns 0 if already past or no due date.
func (t TemporalInfo) KEVDaysRemaining() int {
	if t.KEVDueDate.IsZero() {
		return 0
	}
	if time.Now().After(t.KEVDueDate) {
		return 0
	}
	return int(time.Until(t.KEVDueDate).Hours() / 24)
}

// IsRecentlyDiscovered returns true if published within the last 30 days.
func (t TemporalInfo) IsRecentlyDiscovered() bool {
	if t.Published.IsZero() {
		return false
	}
	return time.Since(t.Published) < 30*24*time.Hour
}

// IsRecentlyUpdated returns true if modified within the last 7 days.
func (t TemporalInfo) IsRecentlyUpdated() bool {
	if t.Modified.IsZero() {
		return false
	}
	return time.Since(t.Modified) < 7*24*time.Hour
}

// FormatAge returns a human-readable age string.
func FormatAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days == 0:
		return "today"
	case days == 1:
		return "1 day"
	case days < 7:
		return fmt.Sprintf("%d days", days)
	case days < 30:
		weeks := days / 7
		if weeks == 1 {
			return "1 week"
		}
		return fmt.Sprintf("%d weeks", weeks)
	case days < 365:
		months := days / 30
		if months == 1 {
			return "1 month"
		}
		return fmt.Sprintf("%d months", months)
	default:
		years := days / 365
		if years == 1 {
			return "1 year"
		}
		return fmt.Sprintf("%d years", years)
	}
}

// FormatRelativeDate returns a date with relative time indicator.
func FormatRelativeDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s (%s ago)", t.Format("2006-01-02"), FormatAge(time.Since(t)))
}

// ParseDate parses a YYYY-MM-DD date string.
func ParseDate(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}
