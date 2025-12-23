package cmd

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/output"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddTriageCommand registers the triage subcommand.
func AddTriageCommand(root *cobra.Command) {
	scanner := NewScanner()
	triageCmd := &cobra.Command{
		Use:           "triage [repo]",
		Short:         "Summarize vulnerabilities and optionally invoke an AI triage agent",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Analyze and prioritize vulnerabilities to help you focus on what matters.

TRIAGE PROCESS:
1. Scan: Detects vulnerabilities (or consumes an existing report).
2. Filter: Applies filters (e.g., ignore unfixed, date ranges).
3. Summarize: Groups issues by severity and package.
4. Analyze: Optionally uses AI to provide context and recommendations.

AI-ASSISTED TRIAGE:
When using an AI agent (like Codex), Deputy sends the vulnerability summary
to the model. The agent can:
• Explain the impact of specific vulnerabilities
• Suggest mitigation strategies
• Prioritize issues based on your project's context

HISTORICAL ANALYSIS:
Use the --as-of flag to see the state of vulnerabilities at a specific point in time.
This is useful for understanding when a vulnerability was introduced or fixed.`,
		Example: `BASIC USAGE:
  # Triage current repository
  deputy triage

  # Triage a remote repository
  deputy triage github.com/hashicorp/vagrant

FILTERING:
  # Ignore vulnerabilities with no known fix
  deputy triage --ignore-unfixed

  # Only show critical vulnerabilities
  deputy triage --policy critical-only.yaml

AI ASSISTANCE:
  # Ask AI to prioritize issues
  deputy triage --agent codex --agent-model gpt-4

  # Resume a previous triage session
  deputy triage --agent codex --agent-thread <thread-id>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTriage(scanner, cmd, args)
		},
	}
	triageCmd.Flags().String("report", "", "Path to JSON output from 'deputy scan --format json'; use '-' for stdin")
	triageCmd.Flags().String("ref", "", "Git ref/commit to scan (defaults to HEAD or WORKING when inside a repo)")
	triageCmd.Flags().StringSlice("ecosystems", nil, "Limit scanning to ecosystems: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	triageCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes when generating the summary")
	triageCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	triageCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	triageCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	triageCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
	triageCmd.Flags().String("agent", "", "Use an AI agent to analyze the triage summary (e.g. 'codex')")
	triageCmd.Flags().String("agent-model", "", "Model identifier to use when --agent is set")
	triageCmd.Flags().String("agent-sandbox", "read-only", "Sandbox policy for AI agent (read-only|workspace-write|danger-full-access)")
	triageCmd.Flags().Bool("agent-full-auto", false, "Enable codex --full-auto mode")
	triageCmd.Flags().String("agent-thread", "", "Resume a previous codex thread ID")
	triageCmd.Flags().Bool("agent-include-plan-tool", true, "Allow codex agent to enable the plan tool")
	triageCmd.Flags().Bool("agent-skip-git-check", true, "Skip codex git repository checks")
	triageCmd.Flags().StringArray("policy", nil, "Path to CEL policy files or bundles to evaluate against triage summaries (repeatable)")
	triageCmd.Flags().Bool("show-db-info", false, "Show database-specific metadata (e.g., review_status) in text output")
	root.AddCommand(triageCmd)
}

// runTriage executes the triage command logic.
// It reads a report or runs a scan, filters vulnerabilities, and generates a summary.
// Optionally, it sends the summary to an AI agent.
func runTriage(scanner *Scanner, cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	format, _ := cmd.Flags().GetString("format")
	agentName, agentOpts := getAgentFlags(cmd)
	policyPaths, _ := cmd.Flags().GetStringArray("policy")
	showDBInfo, _ := cmd.Flags().GetBool("show-db-info")

	repoArg := ""
	if len(args) > 0 {
		repoArg = strings.TrimSpace(args[0])
	}

	var (
		report       triageReport
		repoPath     string
		triageSource string
	)

	if strings.TrimSpace(reportPath) != "" {
		data, err := readReportSource(cmd.InOrStdin(), reportPath)
		if err != nil {
			return err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return fmt.Errorf("report %q is empty", reportPath)
		}
		var scan ScanResult
		if err := json.Unmarshal(data, &scan); err != nil {
			return fmt.Errorf("failed to parse report: %w", err)
		}
		vulns := scan.Vulnerabilities
		if ignoreUnfixed {
			vulns = filterUnfixed(vulns)
		}
		stats := analysis.CategorizeVulnerabilities(vulns)
		cons := analysis.ConsolidateVulnerabilities(vulns)
		report = buildTriageReport(remediationPlanTarget{Repo: scan.Repo, Ref: scan.Ref, Commit: scan.Commit}, stats, cons)
		triageSource = "report"
	} else {
		ctx := cmd.Context()
		ref, _ := cmd.Flags().GetString("ref")
		ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
		scanOpts := inv.ScanOptions{Ecosystems: ecos}
		publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
		publishedAfterStr, _ := cmd.Flags().GetString("published-after")
		asOfStr, _ := cmd.Flags().GetString("as-of")
		beforeT, afterT := parsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)
		exec, err := scanner.executeScan(ctx, repoArg, ref, cmd.Flags().Changed("ref"), scanOpts, beforeT, afterT, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		defer exec.Close()
		repoPath = exec.localRepoPath
		triageSource = "scan"
		vulns := exec.vulnerabilities
		if ignoreUnfixed {
			vulns = filterUnfixed(vulns)
		}
		stats := analysis.CategorizeVulnerabilities(vulns)
		cons := analysis.ConsolidateVulnerabilities(vulns)
		target := remediationPlanTarget{Repo: exec.displayPath, Ref: ref, Commit: exec.commitHash}
		report = buildTriageReport(target, stats, cons)
	}

	if err := runTriagePolicies(cmd.Context(), policyPaths, report, cmd.ErrOrStderr()); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		printTriageSummary(cmd.OutOrStdout(), report, showDBInfo)
	case FormatJSON:
		if err := outputTriageJSON(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}

	if strings.TrimSpace(agentName) != "" {
		targetRepo := repoPath
		var err error
		if strings.TrimSpace(targetRepo) == "" {
			targetRepo, err = resolveRepoPath("", repoArg)
			if err != nil {
				return err
			}
		}
		prompt, err := buildCodexTriagePrompt(report)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Sending triage summary (%s) to %s\n", ui.StyleManager.Render("agent"), triageSource, agentName)
		if err := runAgent(cmd.Context(), agentName, prompt, targetRepo, agentOpts, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
			return err
		}
	}

	return nil
}

// runTriagePolicies evaluates policies against the triage report.
// It checks both the overall report and individual top packages.
func runTriagePolicies(ctx context.Context, policyPaths []string, report triageReport, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	reportMap, err := structToMap(report)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "triage", "triage_report", errW); err != nil {
		return err
	}
	targetMap, err := structToMap(report.Target)
	if err != nil {
		return err
	}
	for _, pkg := range report.TopPackages {
		pkgMap, err := structToMap(pkg)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"target":  targetMap,
			"cluster": pkgMap,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "triage", "triage_cluster", errW); err != nil {
			return err
		}
	}
	return nil
}

// printTriageSummary prints a human-readable summary of the triage report.
func printTriageSummary(w io.Writer, report triageReport, showDBInfo bool) {
	doc := triageSummaryDoc(report)
	if len(report.TopPackages) == 0 {
		doc.AddBlank()
		doc.AddLine(output.Span{Text: "No fixable vulnerabilities after filtering.", Style: output.StyleAdded})
		_ = doc.Render(w, output.UIStyles())
		return
	}
	doc.AddBlank()
	title := topImpactedTitle(report)
	doc.AddLine(output.Span{Text: title})
	doc.AddLine(output.Span{Text: "  Severity shown per package = highest vuln severity in that package.", Style: output.StyleMeta})
	_ = doc.Render(w, output.UIStyles())

	for idx, pkg := range report.TopPackages {
		marker := fmt.Sprintf("%d.", idx+1)
		sev := ui.SeverityLabel(pkg.Severity, pkg.SeverityType)
		sevInline := formatSeverityCounts(pkg.SeverityCounts)
		countInline := ""
		if pkg.VulnerabilityCount > 0 {
			if sevInline != "" {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns (%s)", pkg.VulnerabilityCount, sevInline))
			} else {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns", pkg.VulnerabilityCount))
			}
		}
		fix := ""
		if pkg.FixVersion != "" {
			fix = ui.StyleUpgraded.Render("↑ " + pkg.FixVersion)
		}
		fmt.Fprintf(w, "  %s %s %s %s %s\n", marker, ui.StylePackageName.Render(pkg.Package), ui.StyleVersion.Render(pkg.Version), sev, countInline)
		if pkg.Summary != "" {
			fmt.Fprintln(w, "     ", ui.StyleDim.Render(pkg.Summary))
		}
		if fix != "" {
			fmt.Fprintln(w, "     ", fix)
		}
		if len(pkg.AffectedImports) > 0 {
			lines := formatImportSummaries(pkg.AffectedImports, 2, 3)
			if len(lines) > 0 {
				fmt.Fprintln(w, "     ", ui.StyleMeta.Render("Symbol hints (Go/OSV):"))
				for _, line := range lines {
					fmt.Fprintln(w, "       ", ui.StylePath.Render(line))
				}
			}
		}
		if showDBInfo {
			if dbLines := formatDatabaseSpecificInfo(pkg.DatabaseSpecific, 2); len(dbLines) > 0 {
				fmt.Fprintln(w, "     ", ui.StyleMeta.Render("Database info:"))
				for _, line := range dbLines {
					fmt.Fprintln(w, "       ", ui.StyleMeta.Render(line))
				}
			}
		}
	}
}

func triageSummaryDoc(report triageReport) output.Doc {
	var doc output.Doc
	doc.AddLine(output.Span{Text: "Triage Summary:", Style: output.StyleHeader})
	if repo := strings.TrimSpace(report.Target.Repo); repo != "" {
		repoLine := repo
		if report.Target.Ref != "" {
			repoLine = fmt.Sprintf("%s@%s", repoLine, report.Target.Ref)
		}
		doc.AddLine(output.Span{Text: "  Target: "}, output.Span{Text: repoLine, Style: output.StylePackageName})
	}
	if report.Target.Commit != "" {
		doc.AddLine(output.Span{Text: "  Commit: "}, output.Span{Text: report.Target.Commit, Style: output.StyleVersion})
	}
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Critical/High: %d", report.Stats.CriticalSev+report.Stats.HighSeverity)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Medium: %d", report.Stats.MedSeverity)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Low: %d", report.Stats.LowSeverity)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Fixable: %d", report.Stats.FixAvailable)})
	doc.AddLine(output.Span{Text: fmt.Sprintf("  Direct deps affected: %d", report.Stats.DirectDeps)})
	if report.PackagesWithVulns > 0 {
		line := fmt.Sprintf("  Packages with vulns: %d", report.PackagesWithVulns)
		if report.Stats.IndirectDeps > 0 {
			line += fmt.Sprintf(" (direct: %d, indirect: %d)", report.Stats.DirectDeps, report.Stats.IndirectDeps)
		}
		doc.AddLine(output.Span{Text: line})
	}
	return doc
}

func topImpactedTitle(report triageReport) string {
	title := "Top Impacted Packages"
	if report.PackagesWithVulns > len(report.TopPackages) {
		title += fmt.Sprintf(" (showing %d of %d)", len(report.TopPackages), report.PackagesWithVulns)
	}
	return title + ":"
}

// outputTriageJSON writes the triage report as JSON to the provided writer.
func outputTriageJSON(w io.Writer, report triageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// buildTriageReport constructs a triageReport from the target, stats, and consolidated vulnerabilities.
func buildTriageReport(target remediationPlanTarget, stats analysis.VulnerabilityStats, cons []analysis.ConsolidatedVulnerability) triageReport {
	report := triageReport{Target: target, Stats: stats}
	agg := aggregatePackages(cons)
	report.PackagesWithVulns = len(agg)
	report.TopPackages = agg
	if len(report.TopPackages) > 10 {
		report.TopPackages = report.TopPackages[:10]
	}
	return report
}

// triageReport represents the summary of a triage analysis.
type triageReport struct {
	Target            remediationPlanTarget       `json:"target"`
	Stats             analysis.VulnerabilityStats `json:"stats"`
	TopPackages       []triagePackageSummary      `json:"topPackages"`
	PackagesWithVulns int                         `json:"packagesWithVulns"`
}

// triagePackageSummary represents a summary of a single package's vulnerabilities.
type triagePackageSummary struct {
	Package            string                    `json:"package"`
	Version            string                    `json:"version"`
	Severity           string                    `json:"severity"`
	SeverityType       string                    `json:"severityType"`
	FixVersion         string                    `json:"fixVersion,omitempty"`
	IsDirect           bool                      `json:"isDirect"`
	Summary            string                    `json:"summary,omitempty"`
	SampleIDs          []string                  `json:"sampleIDs,omitempty"`
	AffectedImports    []analysis.AffectedImport `json:"affectedImports,omitempty"`
	DatabaseSpecific   map[string]string         `json:"databaseSpecific,omitempty"`
	VulnerabilityCount int                       `json:"vulnerabilityCount"`
	SeverityCounts     map[string]int            `json:"severityCounts,omitempty"`
}

// aggregatePackages aggregates consolidated vulnerabilities into package summaries.
func aggregatePackages(cons []analysis.ConsolidatedVulnerability) []triagePackageSummary {
	type aggInfo struct {
		pkg        string
		version    string
		severity   string
		severityT  string
		priority   int
		fix        string
		summary    string
		ids        []string
		isDirect   bool
		imports    []analysis.AffectedImport
		dbSpecific map[string]string
		counts     map[string]int
		total      int
	}
	pkgMap := map[string]*aggInfo{}
	for _, v := range cons {
		key := v.Package
		if key == "" {
			continue
		}
		priority, _ := consolidatedSeverityPriority(v)
		info, ok := pkgMap[key]
		if !ok {
			info = &aggInfo{pkg: v.Package, version: v.Version, severity: v.Severity, severityT: v.SeverityType, priority: priority, fix: bestFix(v), summary: v.Summary, isDirect: v.IsDirect}
			pkgMap[key] = info
		}
		if len(v.AffectedImports) > 0 {
			info.imports = analysis.MergeAffectedImports(info.imports, v.AffectedImports)
		}
		if len(v.DatabaseSpecific) > 0 {
			info.dbSpecific = mergeStringMap(info.dbSpecific, v.DatabaseSpecific)
		}
		if info.counts == nil {
			info.counts = map[string]int{}
		}
		sevKey := severityBucket(v.Severity, v.SeverityType)
		info.counts[sevKey]++
		info.total++
		if priority > info.priority {
			info.priority = priority
			info.severity = v.Severity
			info.severityT = v.SeverityType
			info.fix = bestFix(v)
			if v.Summary != "" {
				info.summary = v.Summary
			}
			info.version = v.Version
			info.isDirect = v.IsDirect
		}
		if v.PrimaryID != "" {
			info.ids = append(info.ids, v.PrimaryID)
		}
	}
	list := make([]triagePackageSummary, 0, len(pkgMap))
	for _, info := range pkgMap {
		list = append(list, triagePackageSummary{
			Package:            info.pkg,
			Version:            info.version,
			Severity:           info.severity,
			SeverityType:       info.severityT,
			FixVersion:         info.fix,
			IsDirect:           info.isDirect,
			Summary:            info.summary,
			SampleIDs:          info.ids,
			AffectedImports:    info.imports,
			DatabaseSpecific:   info.dbSpecific,
			VulnerabilityCount: info.total,
			SeverityCounts:     info.counts,
		})
	}
	slices.SortFunc(list, func(a, b triagePackageSummary) int {
		pa, _ := severityRank(a.Severity)
		pb, _ := severityRank(b.Severity)
		if pa != pb {
			// higher severity first
			if pa > pb {
				return -1
			}
			return 1
		}
		if a.IsDirect != b.IsDirect {
			// direct first
			if a.IsDirect {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, b.Version)
	})
	return list
}

// severityBucket normalizes severities into coarse buckets for counting.
func severityBucket(sev, sevType string) string {
	up := strings.ToUpper(strings.TrimSpace(sev))
	if sevType == "GHSA" {
		switch up {
		case "CRITICAL":
			return "CRITICAL"
		case "HIGH":
			return "HIGH"
		case "MEDIUM", "MODERATE":
			return "MED"
		case "LOW":
			return "LOW"
		}
	}
	switch up {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MED"
	case "LOW":
		return "LOW"
	}
	score := analysis.ParseCVSSScore(sev)
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MED"
	case score >= 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// formatImportSummaries prepares a compact set of import/symbol hints for display.
func formatImportSummaries(imps []analysis.AffectedImport, maxPaths, maxSymbols int) []string {
	if len(imps) == 0 {
		return nil
	}
	lines := make([]string, 0, len(imps))
	for i, imp := range imps {
		if maxPaths > 0 && i >= maxPaths {
			lines = append(lines, fmt.Sprintf("... %d more import paths", len(imps)-maxPaths))
			break
		}
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		if len(imp.Symbols) == 0 {
			lines = append(lines, path)
			continue
		}
		syms := imp.Symbols
		truncated := false
		if maxSymbols > 0 && len(syms) > maxSymbols {
			syms = syms[:maxSymbols]
			truncated = true
		}
		symStr := strings.Join(syms, ", ")
		if truncated {
			symStr += ", ..."
		}
		lines = append(lines, fmt.Sprintf("%s (%s)", path, symStr))
	}
	return lines
}

// formatSeverityCounts renders a short severity breakdown like "2 HIGH, 1 MED".
func formatSeverityCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	order := []string{"CRITICAL", "HIGH", "MED", "LOW", "UNKNOWN"}
	labels := map[string]string{
		"CRITICAL": "CRIT",
		"HIGH":     "HIGH",
		"MED":      "MED",
		"LOW":      "LOW",
		"UNKNOWN":  "?",
	}
	var parts []string
	for _, key := range order {
		if n := counts[key]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, labels[key]))
		}
	}
	return strings.Join(parts, ", ")
}

// formatDatabaseSpecificInfo flattens database_specific metadata into displayable lines.
// It truncates after maxEntries with a summary entry when provided.
func formatDatabaseSpecificInfo(db map[string]string, maxEntries int) []string {
	if len(db) == 0 {
		return nil
	}
	keys := slices.Sorted(maps.Keys(db))
	lines := make([]string, 0, len(keys))
	for idx, k := range keys {
		if maxEntries > 0 && idx >= maxEntries {
			lines = append(lines, fmt.Sprintf("... %d more entries", len(keys)-maxEntries))
			break
		}
		lines = append(lines, fmt.Sprintf("%s: %s", k, db[k]))
	}
	return lines
}

// mergeStringMap merges string maps, preferring existing keys in base.
func mergeStringMap(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range extra {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		if _, ok := base[k]; ok {
			continue
		}
		base[k] = v
	}
	return base
}

// severityRank returns a numeric rank for a severity string.
func severityRank(sev string) (int, string) {
	up := strings.ToUpper(strings.TrimSpace(sev))
	switch up {
	case "CRITICAL":
		return 4, up
	case "HIGH":
		return 3, up
	case "MEDIUM", "MODERATE":
		return 2, up
	case "LOW":
		return 1, up
	default:
		return 0, up
	}
}

// bestFix returns the best available fix version for a vulnerability.
func bestFix(v analysis.ConsolidatedVulnerability) string {
	if len(v.FixedVersions) == 0 {
		return ""
	}
	if fix := analysis.FindBestFixedVersion(v.FixedVersions, v.Version); fix != "" {
		return fix
	}
	return strings.Join(v.FixedVersions, ",")
}
