package render

import (
	"fmt"
	"strings"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// maxMarkdownVisibleRows caps how many table rows render outside a
// collapsible details block, keeping PR comments skimmable on large diffs
// while the full data stays one click away.
const maxMarkdownVisibleRows = 20

// DiffMarkdown renders a dependency diff response as GitHub-flavored
// markdown, suitable for PR comments and job summaries.
//
// It is a pure view over the deputy.diff.v1 output contract: everything it
// shows derives from the same message `--format json` emits, so CI tooling
// that wants different rendering can consume the JSON instead and lose
// nothing. Counts come from structured fields, never from text.
func DiffMarkdown(resp *diffv1.DiffVulnerabilitiesResponse) string {
	var b strings.Builder

	b.WriteString("## Deputy Dependency Diff\n\n")
	base := resp.GetBase().GetDisplayPath()
	target := resp.GetTarget().GetDisplayPath()
	if base != "" || target != "" {
		fmt.Fprintf(&b, "`%s` → `%s`\n\n", mdCode(base), mdCode(target))
	}

	b.WriteString(diffMarkdownStatusLine(resp))

	writeMarkdownChanges(&b, resp.GetChanges())
	writeMarkdownVulnerabilities(&b, resp)
	writeMarkdownPolicy(&b, resp)

	return b.String()
}

// diffMarkdownStatusLine builds the one-line summary: change counts, new
// vulnerability status, and policy status, separated by middle dots.
func diffMarkdownStatusLine(resp *diffv1.DiffVulnerabilitiesResponse) string {
	var parts []string

	stats := resp.GetChangeStats()
	if stats.GetTotalChanges() == 0 {
		parts = append(parts, "No dependency changes detected")
	} else {
		var counts []string
		if n := stats.GetAddedCount(); n > 0 {
			counts = append(counts, fmt.Sprintf("%d added", n))
		}
		if n := stats.GetRemovedCount(); n > 0 {
			counts = append(counts, fmt.Sprintf("%d removed", n))
		}
		if n := stats.GetUpgradedCount(); n > 0 {
			counts = append(counts, fmt.Sprintf("%d upgraded", n))
		}
		if n := stats.GetDowngradedCount(); n > 0 {
			counts = append(counts, fmt.Sprintf("%d downgraded", n))
		}
		if n := stats.GetUpdatedCount(); n > 0 {
			counts = append(counts, fmt.Sprintf("%d changed", n))
		}
		parts = append(parts, fmt.Sprintf("**%d dependency change%s** (%s)", stats.GetTotalChanges(), pluralMD(int(stats.GetTotalChanges())), strings.Join(counts, ", ")))
	}

	// Vulnerability status renders only when a scan ran (stats present).
	if vstats := resp.GetStats(); vstats != nil {
		if n := vstats.GetAddedCount(); n > 0 {
			parts = append(parts, fmt.Sprintf("❗ %d new vulnerabilit%s", n, pluralYMD(int(n))))
		} else {
			parts = append(parts, "✅ no new vulnerabilities")
		}
	}

	if resp.GetPolicyFilesEvaluated() > 0 {
		denies, warns := 0, 0
		for _, act := range resp.GetPolicyActions() {
			switch act.GetType() {
			case policyv1.ActionType_ACTION_TYPE_DENY:
				denies++
			case policyv1.ActionType_ACTION_TYPE_WARN:
				warns++
			}
		}
		switch {
		case denies > 0:
			parts = append(parts, fmt.Sprintf("❗ %d policy denial%s", denies, pluralMD(denies)))
		case warns > 0:
			parts = append(parts, fmt.Sprintf("⚠️ %d policy warning%s", warns, pluralMD(warns)))
		default:
			parts = append(parts, "✅ policies passed")
		}
	}

	return strings.Join(parts, " · ") + "\n"
}

// writeMarkdownChanges renders the dependency changes table, collapsing the
// tail into a details block past maxMarkdownVisibleRows.
func writeMarkdownChanges(b *strings.Builder, changes []*diffv1.PackageChange) {
	if len(changes) == 0 {
		return
	}

	b.WriteString("\n### Dependency changes\n\n")

	header := "| | Package | Version | Licenses | |\n| :-: | --- | --- | --- | :-: |\n"
	b.WriteString(header)

	visible := min(len(changes), maxMarkdownVisibleRows)
	for _, c := range changes[:visible] {
		b.WriteString(markdownChangeRow(c))
	}
	if rest := changes[visible:]; len(rest) > 0 {
		fmt.Fprintf(b, "\n<details><summary>… and %d more change%s</summary>\n\n", len(rest), pluralMD(len(rest)))
		b.WriteString(header)
		for _, c := range rest {
			b.WriteString(markdownChangeRow(c))
		}
		b.WriteString("\n</details>\n")
	}
}

// markdownChangeRow renders one dependency change as a table row.
func markdownChangeRow(c *diffv1.PackageChange) string {
	symbol := "~"
	version := ""
	switch c.GetChangeKind() {
	case diffv1.ChangeKind_CHANGE_KIND_ADDED:
		symbol = "+"
		version = fmt.Sprintf("`%s`", mdCode(c.GetTargetVersion()))
	case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
		symbol = "−"
		version = fmt.Sprintf("`%s`", mdCode(c.GetBaseVersion()))
	case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
		symbol = "↑"
		version = fmt.Sprintf("`%s` → `%s`", mdCode(c.GetBaseVersion()), mdCode(c.GetTargetVersion()))
	case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
		symbol = "↓"
		version = fmt.Sprintf("`%s` → `%s`", mdCode(c.GetBaseVersion()), mdCode(c.GetTargetVersion()))
	default:
		version = fmt.Sprintf("`%s` → `%s`", mdCode(c.GetBaseVersion()), mdCode(c.GetTargetVersion()))
	}

	directness := "indirect"
	if c.GetIsDirect() {
		directness = "direct"
	}

	return fmt.Sprintf("| %s | `%s` | %s | %s | %s |\n",
		symbol,
		mdCode(c.GetPackage().GetName()),
		version,
		mdCell(strings.Join(c.GetPackage().GetLicenses(), ", ")),
		directness,
	)
}

// writeMarkdownVulnerabilities renders the newly-introduced vulnerability
// table and the collapsed pre-existing set.
func writeMarkdownVulnerabilities(b *strings.Builder, resp *diffv1.DiffVulnerabilitiesResponse) {
	added := resp.GetAddedVulnerabilities()
	unchanged := resp.GetUnchangedVulnerabilities()

	if len(added) > 0 {
		fmt.Fprintf(b, "\n### ❗ Newly introduced vulnerabilities (%d)\n\n", len(added))
		writeMarkdownFindingTable(b, added, resp.GetAdvisories())
	}

	if len(unchanged) > 0 {
		// Not "unchanged dependencies": an upgraded package whose advisory
		// already affected its base version is reclassified into this bucket,
		// so the set includes dependencies listed in the changes table above.
		// What unites them is that this diff did not introduce them.
		fmt.Fprintf(b, "\n<details><summary>%d pre-existing vulnerabilit%s not introduced by this change</summary>\n\n",
			len(unchanged), pluralYMD(len(unchanged)))
		writeMarkdownFindingTable(b, unchanged, resp.GetAdvisories())
		b.WriteString("\n</details>\n")
	}
}

// writeMarkdownFindingTable renders findings as an ID/severity/package/fix
// table, linking IDs to their OSV advisory pages.
func writeMarkdownFindingTable(b *strings.Builder, findings []*vulnerabilityv1.Finding, advisories map[string]*vulnerabilityv1.Advisory) {
	b.WriteString("| ID | Severity | Package | Fixed in |\n| --- | --- | --- | --- |\n")
	visible := min(len(findings), maxMarkdownVisibleRows)
	for _, f := range findings[:visible] {
		advisory := f.GetAdvisory()
		if advisory == nil {
			advisory = advisories[f.GetAdvisoryId()]
		}
		pkg := f.GetPackage().GetName()
		if v := f.GetPackage().GetVersion(); v != "" {
			pkg += " @ " + v
		}
		fmt.Fprintf(b, "| [%s](https://osv.dev/vulnerability/%s) | %s | `%s` | %s |\n",
			mdCell(f.GetAdvisoryId()),
			mdCell(f.GetAdvisoryId()),
			severityLabel(advisory.GetSeverity()),
			mdCode(pkg),
			mdCell(strings.Join(advisory.GetFixedVersions(), ", ")),
		)
	}
	if rest := len(findings) - visible; rest > 0 {
		fmt.Fprintf(b, "\n… and %d more (see `--format json` for the full set)\n", rest)
	}
}

// writeMarkdownPolicy renders policy results grouped and deduplicated the
// same way the CLI section is, with subjects collapsed into details blocks.
func writeMarkdownPolicy(b *strings.Builder, resp *diffv1.DiffVulnerabilitiesResponse) {
	if resp.GetPolicyFilesEvaluated() == 0 {
		return
	}

	b.WriteString("\n### Policy evaluation\n\n")

	groups := groupPolicyActions(resp.GetPolicyActions())
	if len(groups) == 0 {
		fmt.Fprintf(b, "✅ %d policy file%s evaluated, all rules passed\n",
			resp.GetPolicyFilesEvaluated(), pluralMD(int(resp.GetPolicyFilesEvaluated())))
		return
	}

	for _, g := range groups {
		marker := "⚠️ WARN"
		if g.actionType == policyv1.ActionType_ACTION_TYPE_DENY {
			marker = "❗ DENY"
		}
		fmt.Fprintf(b, "- %s **%s** (`%s`): %s", marker, mdCell(g.ruleName), mdCode(g.policyName), mdCell(g.reason))
		if g.count > 1 {
			fmt.Fprintf(b, " — %d %s", g.count, policySubjectNoun(g))
		}
		b.WriteString("\n")
		if len(g.subjects) > 0 {
			fmt.Fprintf(b, "  <details><summary>Show %d %s</summary>\n\n", len(g.subjects), policySubjectNoun(g))
			for _, s := range g.subjects {
				fmt.Fprintf(b, "  - `%s`\n", mdCode(formatPolicySubject(s)))
			}
			b.WriteString("\n  </details>\n")
		}
		if rem := strings.TrimSpace(g.remediation); rem != "" {
			fmt.Fprintf(b, "  _Remediation: %s_\n", mdCell(rem))
		}
	}
}

// severityLabel renders a normalized severity as a short label, e.g.
// "CRITICAL"; unknown or missing severities render as "UNKNOWN".
func severityLabel(s *vulnerabilityv1.Severity) string {
	level := s.GetLevel().String()
	label := strings.TrimPrefix(level, "SEVERITY_LEVEL_")
	if label == "" || label == "UNSPECIFIED" {
		return "UNKNOWN"
	}
	return label
}

// mdCell sanitizes arbitrary text for use inside a markdown table cell:
// pipes are escaped and newlines flattened so a value can never break the
// table structure.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// mdCode sanitizes text destined for inline code spans: backticks would
// terminate the span and pipes would break enclosing tables, so both are
// replaced.
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// pluralMD returns "s" when n is not 1.
func pluralMD(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// pluralYMD returns "y" or "ies" for words like vulnerability.
func pluralYMD(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
