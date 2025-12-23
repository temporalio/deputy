package analysis

import (
	"time"
)

// VulnFilter is a predicate that returns true if a vulnerability should be included.
type VulnFilter func(Vulnerability) bool

// FilterVulnerabilities applies a list of filters to vulnerabilities.
// A vulnerability is included only if all filters return true.
func FilterVulnerabilities(vulns []Vulnerability, filters ...VulnFilter) []Vulnerability {
	if len(vulns) == 0 || len(filters) == 0 {
		return vulns
	}
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		include := true
		for _, f := range filters {
			if !f(v) {
				include = false
				break
			}
		}
		if include {
			out = append(out, v)
		}
	}
	return out
}

// HasFix returns a filter that includes only vulnerabilities with applicable fixes.
func HasFix() VulnFilter {
	return func(v Vulnerability) bool {
		if len(v.FixedVersions) == 0 {
			return false
		}
		return FindBestFixedVersion(v.FixedVersions, v.Version) != ""
	}
}

// PublishedAfter returns a filter that includes vulnerabilities published on or after the given time.
// Vulnerabilities with unparseable or missing publish dates are excluded.
func PublishedAfter(t time.Time) VulnFilter {
	if t.IsZero() {
		return func(Vulnerability) bool { return true }
	}
	return func(v Vulnerability) bool {
		pt := parsePublishedTime(v.Published)
		if pt.IsZero() {
			return false
		}
		return !pt.Before(t)
	}
}

// PublishedBefore returns a filter that includes vulnerabilities published on or before the given time.
// Vulnerabilities with unparseable or missing publish dates are included (conservative approach).
func PublishedBefore(t time.Time) VulnFilter {
	if t.IsZero() {
		return func(Vulnerability) bool { return true }
	}
	return func(v Vulnerability) bool {
		pt := parsePublishedTime(v.Published)
		if pt.IsZero() {
			return true // unknown date, include conservatively
		}
		return !pt.After(t)
	}
}

// SeverityAtLeast returns a filter that includes only vulnerabilities at or above the given severity.
// Severity order: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN
func SeverityAtLeast(minSeverity string) VulnFilter {
	minLevel := ParseSeverity(minSeverity)
	return func(v Vulnerability) bool {
		return ParseSeverity(v.Severity).Score() >= minLevel.Score()
	}
}

// IsDirect returns a filter that includes only direct dependencies.
func IsDirect() VulnFilter {
	return func(v Vulnerability) bool {
		return v.IsDirect
	}
}

// parsePublishedTime parses the Published field from a vulnerability.
func parsePublishedTime(published string) time.Time {
	if published == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, published); err == nil {
		return t
	}
	// Fallback: attempt date-only parse
	if len(published) >= 10 {
		if t, err := time.Parse("2006-01-02", published[:10]); err == nil {
			return t
		}
	}
	return time.Time{}
}
