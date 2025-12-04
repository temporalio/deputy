package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Predefined lipgloss style palette used by CLI presentation layers. Grouping
// styles here keeps formatting concerns separate from formatting logic.
var (
	StyleAdded      = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")).Bold(true)
	StyleRemoved    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)
	StyleHeader     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true)
	StyleDim        = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	StyleAlias      = lipgloss.NewStyle().Foreground(lipgloss.Color("#BBBBBB")).Bold(true)
	StyleAliasOther = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")).Bold(true)
	StyleMeta       = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Italic(true)
	StyleBold       = lipgloss.NewStyle().Bold(true)
	StyleUpgraded   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Bold(true)
	StyleDowngraded = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	StyleNeutral    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

	StylePackageName    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	StyleVersion        = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	StyleLicense        = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	StyleUpdateArrow    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Faint(true)
	StyleDowngradeArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Faint(true)
	StyleSymbol         = lipgloss.NewStyle().Bold(true)
	StylePath           = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6E6FA"))
	StyleManager        = lipgloss.NewStyle().Foreground(lipgloss.Color("#7FDBFF")).Faint(true)

	// Severity-specific styles for consistent vulnerability display
	StyleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)

	// Policy-related styles for proxy output
	StylePolicyFile = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")) // Sky blue - file reference
	StylePolicyRule = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0C4DE")) // Light steel blue - rule name
	StyleSeparator  = lipgloss.NewStyle().Foreground(lipgloss.Color("#708090")) // Slate gray - punctuation
)

// SeverityLabel returns a consistently styled severity label in the format [CRITICAL], [HIGH], [MED], [LOW], or [?].
// It normalizes GHSA-style severity names (CRITICAL, HIGH, MODERATE/MEDIUM, LOW) and CVSS scores.
func SeverityLabel(severity, severityType string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))

	// Handle GHSA-style severity names
	if severityType == "GHSA" || isGHSASeverity(sev) {
		switch sev {
		case "CRITICAL":
			return StyleCritical.Render("[CRITICAL]")
		case "HIGH":
			return StyleRemoved.Render("[HIGH]")
		case "MODERATE", "MEDIUM":
			return StyleDowngraded.Render("[MED]")
		case "LOW":
			return StyleVersion.Render("[LOW]")
		}
	}

	// Try to parse as CVSS score
	score := parseCVSSScoreSimple(severity)
	return ScoreLabel(score)
}

// ScoreLabel returns a styled severity label based on a numeric CVSS score.
func ScoreLabel(score float64) string {
	switch {
	case score >= 9.0:
		return StyleCritical.Render("[CRITICAL]")
	case score >= 7.0:
		return StyleRemoved.Render("[HIGH]")
	case score >= 4.0:
		return StyleDowngraded.Render("[MED]")
	case score >= 0.0:
		return StyleVersion.Render("[LOW]")
	default:
		return StyleVersion.Render("[?]")
	}
}

// isGHSASeverity checks if a severity string looks like a GHSA severity name.
func isGHSASeverity(sev string) bool {
	switch sev {
	case "CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW":
		return true
	}
	return false
}

// parseCVSSScoreSimple extracts a CVSS score from common formats.
// Returns -1 if no score could be parsed.
func parseCVSSScoreSimple(severity string) float64 {
	severity = strings.TrimSpace(severity)
	if severity == "" {
		return -1
	}

	// Try direct float parse first
	var score float64
	if err := parseFloat(severity, &score); err == nil && score >= 0 && score <= 10 {
		return score
	}

	// Look for CVSS vector pattern and extract score
	if strings.Contains(severity, "CVSS") || strings.Contains(severity, "/AV:") {
		// Try to find a floating point number in the string
		parts := strings.Fields(severity)
		for _, p := range parts {
			if err := parseFloat(p, &score); err == nil && score >= 0 && score <= 10 {
				return score
			}
		}
		// Estimate from vector if present
		return estimateScoreFromVector(severity)
	}

	return -1
}

// parseFloat is a simple float parser helper that parses a float from a string.
func parseFloat(s string, out *float64) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errParseFloat
	}
	var n float64
	var hasDot bool
	var dec float64 = 0.1
	for _, c := range s {
		if c >= '0' && c <= '9' {
			if hasDot {
				n += float64(c-'0') * dec
				dec /= 10
			} else {
				n = n*10 + float64(c-'0')
			}
		} else if c == '.' && !hasDot {
			hasDot = true
		} else {
			break
		}
	}
	*out = n
	if n > 0 || (s[0] == '0' && (len(s) == 1 || s[1] == '.')) {
		return nil
	}
	return errParseFloat
}

var errParseFloat = &parseFloatError{}

type parseFloatError struct{}

func (e *parseFloatError) Error() string { return "parse float error" }

// estimateScoreFromVector provides a rough severity estimate from CVSS vector components.
func estimateScoreFromVector(vector string) float64 {
	// Very rough heuristic based on attack vector and impact
	vector = strings.ToUpper(vector)
	score := 5.0 // Base medium

	if strings.Contains(vector, "AV:N") {
		score += 1.5 // Network accessible
	}
	if strings.Contains(vector, "AC:L") {
		score += 1.0 // Low complexity
	}
	if strings.Contains(vector, "PR:N") {
		score += 0.5 // No privileges required
	}
	if strings.Contains(vector, "C:H") || strings.Contains(vector, "I:H") || strings.Contains(vector, "A:H") {
		score += 1.5 // High impact
	}
	if strings.Contains(vector, "C:N") && strings.Contains(vector, "I:N") {
		score -= 1.0 // No confidentiality/integrity impact
	}

	if score > 10 {
		score = 9.9
	}
	if score < 0 {
		score = 0
	}
	return score
}
