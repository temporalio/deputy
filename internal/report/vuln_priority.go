package report

import (
	"strings"

	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/picatz/deputy/internal/vulnerability/severity/cvss"
)

// ConsolidatedSeverityPriority returns a priority tuple (int, float64) for sorting vulnerabilities.
// Higher values indicate higher priority.
func ConsolidatedSeverityPriority(v vulnerability.Consolidated) (int, float64) {
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
	score := cvss.ParseScore(v.Severity)
	return int(score*10 + 0.5), score
}
