package vuln

import (
	"fmt"
	"strings"
)

// Severity represents the severity level of a vulnerability using a type-safe enum.
type Severity int

const (
	// SeverityUnknown indicates the severity level is not determined or unavailable.
	SeverityUnknown Severity = iota
	// SeverityLow represents low severity vulnerabilities with minimal impact.
	SeverityLow
	// SeverityMedium represents medium severity vulnerabilities with moderate impact.
	SeverityMedium
	// SeverityHigh represents high severity vulnerabilities with significant impact.
	SeverityHigh
	// SeverityCritical represents critical severity vulnerabilities requiring immediate attention.
	SeverityCritical
)

// String returns the string representation of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity converts a string severity level to the Severity enum.
// It normalizes the input to handle common variations and returns SeverityUnknown
// for unrecognized values.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SeverityLow
	case "MEDIUM", "MODERATE", "MED":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL", "CRIT":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// Score returns a numeric score for severity ordering (higher is more severe).
func (s Severity) Score() int {
	return int(s)
}

// CVSS score thresholds for severity classification per CVSS v3.x specification.
const (
	CVSSScoreCritical = 9.0 // CRITICAL: 9.0 - 10.0
	CVSSScoreHigh     = 7.0 // HIGH: 7.0 - 8.9
	CVSSScoreMedium   = 4.0 // MEDIUM: 4.0 - 6.9
	CVSSScoreLow      = 0.1 // LOW: 0.1 - 3.9 (0.0 is informational/none)
)

// SeverityFromCVSS converts a CVSS score to a Severity level.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= CVSSScoreCritical:
		return SeverityCritical
	case score >= CVSSScoreHigh:
		return SeverityHigh
	case score >= CVSSScoreMedium:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// IsHigherThan returns true if this severity is more severe than the other.
func (s Severity) IsHigherThan(other Severity) bool {
	return s.Score() > other.Score()
}

// SeverityType represents the source or scoring system for a severity rating.
type SeverityType int

const (
	// SeverityTypeUnknown indicates the severity type is not specified.
	SeverityTypeUnknown SeverityType = iota
	// SeverityTypeCVSSv2 indicates Common Vulnerability Scoring System version 2.
	SeverityTypeCVSSv2
	// SeverityTypeCVSSv3 indicates Common Vulnerability Scoring System version 3.
	SeverityTypeCVSSv3
	// SeverityTypeCVSSv4 indicates Common Vulnerability Scoring System version 4.
	SeverityTypeCVSSv4
	// SeverityTypeGHSA indicates GitHub Security Advisory severity rating.
	SeverityTypeGHSA
	// SeverityTypeCustom indicates a custom or vendor-specific severity rating.
	SeverityTypeCustom
)

// String returns the string representation of the severity type.
func (st SeverityType) String() string {
	switch st {
	case SeverityTypeCVSSv2:
		return "CVSS_V2"
	case SeverityTypeCVSSv3:
		return "CVSS_V3"
	case SeverityTypeCVSSv4:
		return "CVSS_V4"
	case SeverityTypeGHSA:
		return "GHSA"
	case SeverityTypeCustom:
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverityType converts a string to the SeverityType enum.
func ParseSeverityType(s string) SeverityType {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CVSS_V2", "CVSSV2":
		return SeverityTypeCVSSv2
	case "CVSS_V3", "CVSSV3":
		return SeverityTypeCVSSv3
	case "CVSS_V4", "CVSSV4":
		return SeverityTypeCVSSv4
	case "GHSA":
		return SeverityTypeGHSA
	case "CUSTOM":
		return SeverityTypeCustom
	default:
		return SeverityTypeUnknown
	}
}

// SeverityInfo encapsulates both the severity level and its source/type.
type SeverityInfo struct {
	Level    Severity
	Type     SeverityType
	RawScore string // Original CVSS score or severity string
	RawType  string // Original type string for compatibility
}

// NewSeverityInfo creates a SeverityInfo from raw string values.
// This is useful for migrating from string-based severity fields.
func NewSeverityInfo(severityStr, typeStr string) SeverityInfo {
	return SeverityInfo{
		Level:    ParseSeverity(severityStr),
		Type:     ParseSeverityType(typeStr),
		RawScore: severityStr,
		RawType:  typeStr,
	}
}

// IsValid returns true if the severity info has a recognized level and type.
func (si SeverityInfo) IsValid() bool {
	return si.Level != SeverityUnknown && si.Type != SeverityTypeUnknown
}

// String returns a human-readable representation of the severity info.
func (si SeverityInfo) String() string {
	if si.Type != SeverityTypeUnknown {
		return fmt.Sprintf("%s (%s)", si.Level, si.Type)
	}
	return si.Level.String()
}

// FindBestSeverity chooses the most meaningful severity across related vulns.
// It prefers GHSA textual severities when HIGH/CRITICAL, otherwise the highest CVSS score.
func FindBestSeverity(vulns []Vulnerability) (string, string) {
	if len(vulns) == 0 {
		return "", ""
	}
	var bestScore float64 = -1
	var bestSev, bestType string

	// GHSA textual severities (HIGH/CRITICAL) take precedence.
	for _, v := range vulns {
		if v.SeverityType == "GHSA" {
			up := strings.ToUpper(v.Severity)
			if up == "CRITICAL" {
				return v.Severity, v.SeverityType
			}
			if up == "HIGH" && bestSev == "" {
				bestSev, bestType = v.Severity, v.SeverityType
			}
		}
	}

	// Otherwise pick the highest CVSS score.
	for _, v := range vulns {
		score := ParseCVSSScore(v.Severity)
		if score > bestScore {
			bestScore = score
			bestSev = v.Severity
			bestType = v.SeverityType
		}
	}
	return bestSev, bestType
}
