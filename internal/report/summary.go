package report

import (
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	remediation "github.com/temporalio/deputy/internal/remediation"
	"github.com/temporalio/deputy/internal/vulnerability"
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

	// CommandFixableCount counts findings resolved by an action (e.g. pinning)
	// rather than a version upgrade. CommandRemediations lists the distinct
	// commands, in first-seen order (e.g. "deputy pin").
	CommandFixableCount int
	CommandRemediations []string
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

	// Findings whose fix is an action (e.g. pinning) rather than a version
	// upgrade. These are fixable, so they must not fall into "no fix available".
	var cmdRemediations []string
	seenCmd := map[string]bool{}
	commandFixable := 0
	for _, v := range cons {
		cmd := v.CommandRemediation()
		if cmd == "" {
			continue
		}
		commandFixable++
		if !seenCmd[cmd] {
			seenCmd[cmd] = true
			cmdRemediations = append(cmdRemediations, cmd)
		}
	}

	unfixed := int(stats.Unique) - int(stats.FixAvailable) - commandFixable
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
		UnfixedCount:         unfixed,
		StdlibRecommendation: stdlibRec,
		Commands:             commands,
		CommandsHeader:       header,
		CommandFixableCount:  commandFixable,
		CommandRemediations:  cmdRemediations,
	}
}
