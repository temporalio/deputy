package report

import (
	remediation "github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Summary captures counts and recommended actions derived from vulnerabilities.
type Summary struct {
	HasVulnerabilities   bool
	Stats                vulnerability.Stats
	CriticalHighCount    int
	FixAvailableCount    int
	UnfixedCount         int
	StdlibRecommendation string
	Commands             []remediation.Command
	CommandsHeader       string
}

// BuildSummaryFromResult computes summary stats from a ConsolidatedResult.
// This is the preferred API when using ConsolidateAll.
func BuildSummaryFromResult(result vulnerability.ConsolidatedResult) Summary {
	return BuildSummary(result.Vulnerabilities, result.Stats)
}

// BuildSummary computes summary stats and remediation suggestions for vulnerabilities.
func BuildSummary(cons []vulnerability.Consolidated, stats vulnerability.Stats) Summary {
	if len(cons) == 0 {
		return Summary{HasVulnerabilities: false}
	}
	if stats.UniqueVulns == 0 {
		stats = vulnerability.StatsFromConsolidated(cons, len(cons))
	}
	high := stats.CriticalSev + stats.HighSeverity
	unfixed := stats.UniqueVulns - stats.FixAvailable
	if unfixed < 0 {
		unfixed = 0
	}
	commands, stdlibRec := remediation.CommandsFromConsolidated(cons)
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
