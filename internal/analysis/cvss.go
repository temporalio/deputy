package analysis

import (
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

// parseFloat extracts a float64 from a string, returning -1 on error.
func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}
	var result float64
	var decimal float64 = 1
	var foundDot bool
	var digitsFound bool

	for _, r := range s {
		if r >= '0' && r <= '9' {
			digitsFound = true
			digit := float64(r - '0')
			if foundDot {
				decimal *= 0.1
				result += digit * decimal
			} else {
				result = result*10 + digit
			}
		} else if r == '.' && !foundDot {
			foundDot = true
		} else {
			break
		}
	}

	if !digitsFound {
		return -1
	}
	if result >= 0.0 && result <= 10.0 {
		return result
	}
	return -1
}

// ParseCVSSScore interprets common CVSS representations and returns the base score or -1.
func ParseCVSSScore(severity string) float64 {
	// Standard CVSS vector strings (CVSS:3.x/...)
	if strings.HasPrefix(severity, "CVSS:3.1/") {
		if v, err := gocvss31.ParseVector(severity); err == nil {
			return v.BaseScore()
		}
	}
	if strings.HasPrefix(severity, "CVSS:3.0/") {
		if v, err := gocvss30.ParseVector(severity); err == nil {
			return v.BaseScore()
		}
	}

	// Vector with Base: score
	if strings.Contains(severity, "/") {
		parts := strings.Split(severity, "/")
		for _, part := range parts {
			if strings.HasPrefix(part, "Base:") || strings.HasPrefix(part, "base:") {
				scoreStr := strings.TrimPrefix(strings.TrimPrefix(part, "Base:"), "base:")
				if score := parseFloat(scoreStr); score >= 0 {
					return score
				}
			}
		}
	}
	// Direct numeric value
	if score := parseFloat(severity); score >= 0 {
		return score
	}
	// Common labels
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium", "moderate":
		return 5.5
	case "low":
		return 2.5
	default:
		return -1.0
	}
}
