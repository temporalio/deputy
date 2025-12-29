package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
)

// AddTriageCommand registers the triage subcommand.
func AddTriageCommand(root *cobra.Command, service *scan.Service) {
	scanner := NewScanner(service)
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
		triageReport report.TriageReport
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
		var scanReport ScanResult
		if err := json.Unmarshal(data, &scanReport); err != nil {
			return fmt.Errorf("failed to parse report: %w", err)
		}
		findings, advisories := report.SplitVulnerabilities(scanReport.Vulnerabilities)
		scanResult := scan.Result{
			Findings:   findings,
			Advisories: advisories,
			Stats:      scanReport.Stats,
		}
		if ignoreUnfixed {
			scanResult = scan.FilterUnfixed(scanResult)
		}
		cons := vulnerability.Consolidate(scanResult.Findings, scanResult.Advisories)
		triageReport = report.BuildTriageReport(report.Target{Repo: scanReport.Repo, Ref: scanReport.Ref, Commit: scanReport.Commit}, scanResult.Stats, cons)
		triageSource = "report"
	} else {
		ctx := cmd.Context()
		ref, _ := cmd.Flags().GetString("ref")
		ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
		publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
		publishedAfterStr, _ := cmd.Flags().GetString("published-after")
		asOfStr, _ := cmd.Flags().GetString("as-of")
		beforeT, afterT := flags.ParsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)
		exec, err := scanner.service.ScanRepository(ctx, repoArg, ref, cmd.Flags().Changed("ref"), scan.Options{
			Ecosystems:      ecos,
			PublishedBefore: beforeT,
			PublishedAfter:  afterT,
		})
		if err != nil {
			return err
		}
		defer exec.Close()
		for _, warning := range exec.Result.Warnings {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
		}
		repoPath = exec.Result.Target.LocalPath
		triageSource = "scan"
		resultOut := exec.Result
		if ignoreUnfixed {
			resultOut = scan.FilterUnfixed(resultOut)
		}
		cons := vulnerability.Consolidate(resultOut.Findings, resultOut.Advisories)
		target := report.Target{Repo: exec.Result.Target.DisplayPath, Ref: ref, Commit: exec.Result.Target.CommitHash}
		triageReport = report.BuildTriageReport(target, resultOut.Stats, cons)
	}

	if err := runTriagePolicies(cmd.Context(), policyPaths, triageReport, cmd.ErrOrStderr()); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		render.RenderTriageSummary(cmd.OutOrStdout(), triageReport, showDBInfo)
	case FormatJSON:
		if err := outputTriageJSON(cmd.OutOrStdout(), triageReport); err != nil {
			return err
		}
	default:
		return flags.UnsupportedFormatError("--format", format, "text|json")
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
		prompt, err := buildCodexTriagePrompt(triageReport)
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
func runTriagePolicies(ctx context.Context, policyPaths []string, triageReport report.TriageReport, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	reportMap, err := structToMap(triageReport)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportMap, "triage", "triage_report", errW); err != nil {
		return err
	}
	targetMap, err := structToMap(triageReport.Target)
	if err != nil {
		return err
	}
	for _, pkg := range triageReport.TopPackages {
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

// outputTriageJSON writes the triage report as JSON to the provided writer.
func outputTriageJSON(w io.Writer, report report.TriageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
