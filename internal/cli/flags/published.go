package flags

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ParsePublishedFilters parses the date filter flags and returns the before and after times.
func ParsePublishedFilters(errW io.Writer, asOfStr, beforeStr, afterStr string) (time.Time, time.Time) {
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := parseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if beforeStr != "" && beforeT.IsZero() {
		if t, err := parseFlexibleDate(beforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-before %q: %v\n", beforeStr, err)
		}
	}
	if afterStr != "" {
		if t, err := parseFlexibleDate(afterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-after %q: %v\n", afterStr, err)
		}
	}
	return beforeT, afterT
}

// parseFlexibleDate parses common date forms for CLI filtering:
//
//	YYYY -> treated as YYYY-12-31 end of year when used as 'before', or YYYY-01-01 when used as 'after'
//	YYYY-MM -> end of month for 'before', first day for 'after'
//	YYYY-MM-DD -> exact day (inclusive boundaries)
//	RFC3339 / full timestamp -> exact instant
//
// The caller supplies a hint context ("before"|"after"|"asof") to adjust implicit end/start semantics.
func parseFlexibleDate(s string, intent string) (time.Time, error) {
	st := strings.TrimSpace(s)
	if st == "" {
		return time.Time{}, fmt.Errorf("empty date")
	}
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, st); err == nil {
		return t, nil
	}
	// Accept date only forms
	layouts := []string{"2006-01-02", "2006-1-2"}
	for _, l := range layouts {
		if t, err := time.Parse(l, st); err == nil {
			// Interpret as end of day for 'before' boundary to keep inclusivity
			if intent == "before" || intent == "asof" { // inclusive upper bound
				return t.Add(23*time.Hour + 59*time.Minute + 59*time.Second), nil
			}
			return t, nil
		}
	}
	// Year-month
	if len(st) == 7 && st[4] == '-' { // YYYY-MM
		yearMonthLayout := "2006-01"
		if t, err := time.Parse(yearMonthLayout, st); err == nil {
			y := t.Year()
			m := t.Month()
			if intent == "before" || intent == "asof" {
				// end of month
				n := time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Second)
				return n, nil
			}
			return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC), nil
		}
	}
	// Year only
	if len(st) == 4 {
		if y, err := time.Parse("2006", st); err == nil {
			year := y.Year()
			if intent == "before" || intent == "asof" {
				return time.Date(year, 12, 31, 23, 59, 59, 0, time.UTC), nil
			}
			return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized date format: %s", s)
}
