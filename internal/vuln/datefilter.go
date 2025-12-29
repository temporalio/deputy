package vuln

import (
	"fmt"
	"strings"
	"time"
)

// ParseFlexibleDate parses common date forms for CLI filtering:
//
//	YYYY -> treated as YYYY-12-31 end of year when used as 'before', or YYYY-01-01 when used as 'after'
//	YYYY-MM -> end of month for 'before', first day for 'after'
//	YYYY-MM-DD -> exact day (inclusive boundaries)
//	RFC3339 / full timestamp -> exact instant
//
// The caller supplies a hint context ("before"|"after"|"asof") to adjust implicit end/start semantics.
func ParseFlexibleDate(s string, intent string) (time.Time, error) {
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

// FilterVulnerabilitiesByPublished filters vulnerabilities based on published timestamp.
// If before is non-zero, only include vulns with Published <= before.
// If after is non-zero, only include vulns with Published >= after.
// Empty or unparsable Published fields are included unless they violate 'after' constraint.
func FilterVulnerabilitiesByPublished(vs []Vulnerability, after, before time.Time) []Vulnerability {
	if after.IsZero() && before.IsZero() {
		return vs
	}
	out := make([]Vulnerability, 0, len(vs))
	for _, v := range vs {
		if v.Published == "" { // keep if no conflicting constraint
			if !after.IsZero() { // cannot satisfy 'after' reliably, drop conservatively
				continue
			}
			if !before.IsZero() { // unknown publish date, treat as present? choose to include
				out = append(out, v)
				continue
			}
		}
		pt, err := time.Parse(time.RFC3339, v.Published)
		if err != nil {
			// Fallback: attempt date-only parse
			if len(v.Published) >= 10 {
				if t2, err2 := time.Parse("2006-01-02", v.Published[:10]); err2 == nil {
					pt = t2
				}
			}
		}
		if pt.IsZero() {
			if !after.IsZero() { // skip unknown
				continue
			}
			out = append(out, v)
			continue
		}
		if !after.IsZero() && pt.Before(after) {
			continue
		}
		if !before.IsZero() && pt.After(before) {
			continue
		}
		out = append(out, v)
	}
	return out
}
