package report

import (
	analysis "github.com/picatz/deputy/internal/analysis"
	remediation "github.com/picatz/deputy/internal/remediation"
)

// Summary captures counts and recommended actions derived from vulnerabilities.
type Summary struct {
	HasVulnerabilities   bool
	Stats                analysis.VulnerabilityStats
	CriticalHighCount    int
	FixAvailableCount    int
	UnfixedCount         int
	StdlibRecommendation string
	Commands             []remediation.Command
	CommandsHeader       string
}

// BuildSummary computes summary stats and remediation suggestions for vulnerabilities.
func BuildSummary(vulns []analysis.Vulnerability) Summary {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		return Summary{HasVulnerabilities: false}
	}
	stats := analysis.CategorizeVulnerabilities(vulns)
	high := stats.CriticalSev + stats.HighSeverity
	unfixed := stats.UniqueVulns - stats.FixAvailable
	commands, stdlibRec := remediation.CommandsFromVulnerabilities(vulns)
	header := "Upgrade affected modules"
	if high > 0 {
		header = "Upgrade critical/high modules first"
	}
	return Summary{
		HasVulnerabilities:   true,
		Stats:                stats,
		CriticalHighCount:    high,
		FixAvailableCount:    stats.FixAvailable,
		UnfixedCount:         unfixed,
		StdlibRecommendation: stdlibRec,
		Commands:             commands,
		CommandsHeader:       header,
	}
}
