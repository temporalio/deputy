package report

import (
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
)

// ConsolidatedSeverityPriority returns a priority tuple (int, float64) for sorting vulnerabilities.
// Higher values indicate higher priority.
func ConsolidatedSeverityPriority(v analysis.ConsolidatedVulnerability) (int, float64) {
	sev := strings.ToUpper(strings.TrimSpace(v.Severity))
	if v.SeverityType == "GHSA" {
		switch sev {
		case "CRITICAL":
			return 400, 10.0
		case "HIGH":
			return 300, 8.0
		case "MODERATE", "MEDIUM":
			return 200, 5.0
		case "LOW":
			return 100, 2.0
		}
	}
	score := analysis.ParseCVSSScore(v.Severity)
	return int(score*10 + 0.5), score
}
