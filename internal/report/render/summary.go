package render

import (
	"fmt"
	"strings"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/output"
)

// TargetSummary identifies the repository and reference for a summary.
type TargetSummary struct {
	Repo   string
	Ref    string
	Commit string
}

// DiffHeaderDoc builds the header for dependency diff output.
func DiffHeaderDoc(baseRef, targetRef string) output.Doc {
	var doc output.Doc
	doc.AddLine(
		output.Span{Text: "Comparing dependencies:", Style: output.StyleHeader},
		output.Span{Text: " "},
		output.Span{Text: baseRef, Style: output.StyleVersion},
		output.Span{Text: " → "},
		output.Span{Text: targetRef, Style: output.StyleVersion},
	)
	return doc
}

// TriageSummaryDoc builds the summary header for triage output.
func TriageSummaryDoc(target TargetSummary, stats vulnerabilityv1.Stats, packagesWithVulns int) output.Doc {
	var doc output.Doc
	doc.AddLine(output.Span{Text: "Triage Summary:", Style: output.StyleHeader})
	if repo := strings.TrimSpace(target.Repo); repo != "" {
		repoLine := repo
		if target.Ref != "" {
			repoLine = fmt.Sprintf("%s@%s", repoLine, target.Ref)
		}
		doc.AddLine(output.Span{Text: "  Target: "}, output.Span{Text: repoLine, Style: output.StylePackageName})
	}
	if target.Commit != "" {
		doc.AddLine(output.Span{Text: "  Commit: "}, output.Span{Text: target.Commit, Style: output.StyleVersion})
	}
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Critical/High: %d", stats.Critical+stats.High)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Medium: %d", stats.Medium)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Low: %d", stats.Low)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Fixable: %d", stats.FixAvailable)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Direct deps affected: %d", stats.DirectDeps)})
	if packagesWithVulns > 0 {
		line := fmt.Sprintf("  Packages with vulns: %d", packagesWithVulns)
		if stats.IndirectDeps > 0 {
			line += fmt.Sprintf(" (direct: %d, indirect: %d)", stats.DirectDeps, stats.IndirectDeps)
		}
		doc.AddLine(output.Span{Text: line})
	}
	return doc
}

// FixSummaryDoc builds the remediation plan summary and reports whether it has runnable commands.
func FixSummaryDoc(target TargetSummary, stdlibUpgrade string, totalCommands, runnableCommands, commandsCount int) (output.Doc, bool) {
	var doc output.Doc
	doc.AddLine(output.Span{Text: "Remediation Plan:", Style: output.StyleHeader})
	if repo := strings.TrimSpace(target.Repo); repo != "" {
		repoLine := repo
		if target.Ref != "" {
			repoLine = fmt.Sprintf("%s@%s", repoLine, target.Ref)
		}
		doc.AddLine(output.Span{Text: "  Target: "}, output.Span{Text: repoLine, Style: output.StylePackageName})
	}
	if target.Commit != "" {
		doc.AddLine(output.Span{Text: "  Commit: "}, output.Span{Text: target.Commit, Style: output.StyleVersion})
	}
	if stdlibUpgrade != "" {
		doc.AddLine(
			output.Span{Text: "  • "},
			output.Span{Text: "Upgrade Go toolchain to", Style: output.StyleBold},
			output.Span{Text: " "},
			output.Span{Text: stdlibUpgrade, Style: output.StyleUpgraded},
		)
	}
	if commandsCount == 0 {
		doc.AddLine(output.Span{Text: "  • "}, output.Span{Text: "No dependency upgrades with fixes (report contains only unfixed issues).", Style: output.StyleMeta})
		return doc, false
	}
	doc.AddLine(
		output.Span{Text: "  • "},
		output.Span{Text: "Apply dependency upgrades", Style: output.StyleBold},
		output.Span{Text: fmt.Sprintf(" (%d total, %d runnable)", totalCommands, runnableCommands)},
	)
	return doc, true
}

// TopImpactedTitle builds the "Top Impacted Packages" title line with count context.
func TopImpactedTitle(totalPackages, shownPackages int) string {
	title := "Top Impacted Packages"
	if totalPackages > shownPackages {
		title += fmt.Sprintf(" (showing %d of %d)", shownPackages, totalPackages)
	}
	return title + ":"
}
