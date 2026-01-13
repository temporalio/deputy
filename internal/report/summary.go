package report

import (
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	remediation "github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Summary captures counts and recommended actions derived from vulnerabilities.
type Summary struct {
	HasVulnerabilities   bool
	Stats                vulnerabilityv1.Stats
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
func BuildSummary(cons []vulnerability.Consolidated, stats vulnerabilityv1.Stats) Summary {
	if len(cons) == 0 {
		return Summary{HasVulnerabilities: false}
	}
	if stats.Unique == 0 {
		stats = vulnerability.StatsFromConsolidated(cons, len(cons))
	}
	high := stats.Critical + stats.High
	unfixed := stats.Unique - stats.FixAvailable
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
		CriticalHighCount:    int(high),
		FixAvailableCount:    int(stats.FixAvailable),
		UnfixedCount:         int(unfixed),
		StdlibRecommendation: stdlibRec,
		Commands:             commands,
		CommandsHeader:       header,
	}
}
