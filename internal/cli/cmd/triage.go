package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
	inv "github.com/picatz/deputy/internal/inventory"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddTriageCommand registers the triage subcommand.
func AddTriageCommand(root *cobra.Command) {
	scanner := NewScanner()
	triageCmd := &cobra.Command{
		Use:   "triage [repo]",
		Short: "Summarize vulnerabilities and optionally invoke an AI triage agent",
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
	triageCmd.Flags().StringSlice("ecosystems", nil, "Limit scanning to specific ecosystems (defaults to all supported)")
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
	root.AddCommand(triageCmd)
}

// runTriage executes the triage command logic.
// It reads a report or runs a scan, filters vulnerabilities, and generates a summary.
// Optionally, it sends the summary to an AI agent.
func runTriage(scanner *Scanner, cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	format, _ := cmd.Flags().GetString("format")
	agentName, _ := cmd.Flags().GetString("agent")
	agentModel, _ := cmd.Flags().GetString("agent-model")
	agentSandbox, _ := cmd.Flags().GetString("agent-sandbox")
	agentFullAuto, _ := cmd.Flags().GetBool("agent-full-auto")
	agentThreadID, _ := cmd.Flags().GetString("agent-thread")
	agentIncludePlanTool, _ := cmd.Flags().GetBool("agent-include-plan-tool")
	agentSkipGitCheck, _ := cmd.Flags().GetBool("agent-skip-git-check")
	policyPaths, _ := cmd.Flags().GetStringArray("policy")

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
	case "", "text":
		printTriageSummary(report)
	case "json":
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
		agentOpts := agentInvocationOptions{
			Model:            agentModel,
			Sandbox:          agentSandbox,
			FullAuto:         agentFullAuto,
			ThreadID:         agentThreadID,
			IncludePlanTool:  agentIncludePlanTool,
			SkipGitRepoCheck: agentSkipGitCheck,
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

// printTriageSummary prints a human-readable summary of the triage report to stdout.
func printTriageSummary(report triageReport) {
	fmt.Println(ui.StyleHeader.Render("Triage Summary:"))
	if repo := strings.TrimSpace(report.Target.Repo); repo != "" {
		repoLine := repo
		if report.Target.Ref != "" {
			repoLine = fmt.Sprintf("%s@%s", repoLine, report.Target.Ref)
		}
		fmt.Println("  Target:", ui.StylePackageName.Render(repoLine))
	}
	if report.Target.Commit != "" {
		fmt.Println("  Commit:", ui.StyleVersion.Render(report.Target.Commit))
	}
	fmt.Printf("  Critical/High: %d\n", report.Stats.CriticalSev+report.Stats.HighSeverity)
	fmt.Printf("  Medium: %d\n", report.Stats.MedSeverity)
	fmt.Printf("  Low: %d\n", report.Stats.LowSeverity)
	fmt.Printf("  Fixable: %d\n", report.Stats.FixAvailable)
	fmt.Printf("  Direct deps affected: %d\n", report.Stats.DirectDeps)
	if len(report.TopPackages) == 0 {
		fmt.Println("\n" + ui.StyleAdded.Render("No fixable vulnerabilities after filtering."))
		return
	}
	fmt.Println("\nTop Impacted Packages:")
	for idx, pkg := range report.TopPackages {
		marker := fmt.Sprintf("%d.", idx+1)
		sev := ui.SeverityLabel(pkg.Severity, pkg.SeverityType)
		fix := ""
		if pkg.FixVersion != "" {
			fix = ui.StyleUpgraded.Render("↑ " + pkg.FixVersion)
		}
		fmt.Printf("  %s %s %s %s\n", marker, ui.StylePackageName.Render(pkg.Package), ui.StyleVersion.Render(pkg.Version), sev)
		if pkg.Summary != "" {
			fmt.Println("     ", ui.StyleDim.Render(pkg.Summary))
		}
		if fix != "" {
			fmt.Println("     ", fix)
		}
	}
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
	report.TopPackages = agg
	if len(report.TopPackages) > 10 {
		report.TopPackages = report.TopPackages[:10]
	}
	return report
}

// triageReport represents the summary of a triage analysis.
type triageReport struct {
	Target      remediationPlanTarget       `json:"target"`
	Stats       analysis.VulnerabilityStats `json:"stats"`
	TopPackages []triagePackageSummary      `json:"topPackages"`
}

// triagePackageSummary represents a summary of a single package's vulnerabilities.
type triagePackageSummary struct {
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Severity     string   `json:"severity"`
	SeverityType string   `json:"severityType"`
	FixVersion   string   `json:"fixVersion,omitempty"`
	IsDirect     bool     `json:"isDirect"`
	Summary      string   `json:"summary,omitempty"`
	SampleIDs    []string `json:"sampleIDs,omitempty"`
}

// aggregatePackages aggregates consolidated vulnerabilities into package summaries.
func aggregatePackages(cons []analysis.ConsolidatedVulnerability) []triagePackageSummary {
	type aggInfo struct {
		pkg       string
		version   string
		severity  string
		severityT string
		priority  int
		fix       string
		summary   string
		ids       []string
		isDirect  bool
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
			Package:      info.pkg,
			Version:      info.version,
			Severity:     info.severity,
			SeverityType: info.severityT,
			FixVersion:   info.fix,
			IsDirect:     info.isDirect,
			Summary:      info.summary,
			SampleIDs:    info.ids,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		pi, _ := severityRank(list[i].Severity)
		pj, _ := severityRank(list[j].Severity)
		if pi != pj {
			return pi > pj
		}
		if list[i].IsDirect != list[j].IsDirect {
			return list[i].IsDirect
		}
		if list[i].Package != list[j].Package {
			return list[i].Package < list[j].Package
		}
		return list[i].Version < list[j].Version
	})
	return list
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
