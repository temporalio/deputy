package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/policy"
	remediation "github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// remediationPlan represents a structured plan for remediating vulnerabilities.
type remediationPlan struct {
	Target        report.Target          `json:"target"`
	StdlibUpgrade string                 `json:"stdlibUpgrade,omitempty"`
	Commands      []remediation.Command  `json:"commands"`
	Stats         remediationPlanSummary `json:"stats"`
}

// remediationPlanSummary provides statistics about the remediation plan.
type remediationPlanSummary struct {
	TotalCommands    int `json:"totalCommands"`
	RunnableCommands int `json:"runnableCommands"`
}

// AddFixCommand registers the fix subcommand with the root command.
// It configures flags for report input, plan input, and AI agent options.
func AddFixCommand(root *cobra.Command, service *scan.Service) {
	scanner := NewScanner(service)
	fixCmd := &cobra.Command{
		Use:           "fix [repo]",
		Aliases:       []string{"f"},
		Short:         "Generate and optionally apply remediation steps",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Generate and apply remediation plans for security vulnerabilities.

REMEDIATION WORKFLOW:
1. Scan: Detects vulnerabilities in the repository (or uses an existing report).
2. Plan: Generates a set of remediation commands (e.g., 'go get', 'npm install').
3. Apply: Optionally executes the commands to fix the issues.

AUTOMATED FIXES:
Deputy can automatically generate upgrade commands for:
• Go modules (go get)
• npm packages (npm install)
• PyPI packages (pip install)
• RubyGems (bundle update)

AI-ASSISTED REMEDIATION:
For complex issues or when standard upgrades aren't enough, Deputy can delegate
remediation to an AI agent (like Codex). The agent can:
• Analyze the vulnerability context
• Propose code changes or configuration updates
• Execute fixes in a sandboxed environment

PLAN MANAGEMENT:
Remediation plans can be saved to JSON and reviewed before application. This is
useful for CI/CD pipelines where you want to generate a plan in one step and
apply it in another (after approval).`,
		Example: `BASIC USAGE:
  # Scan and generate a remediation plan
  deputy fix

  # Scan and immediately apply fixes (interactive)
  deputy fix --apply .

ADVANCED WORKFLOWS:
  # Generate a plan and save it to a file
  deputy fix --format json > plan.json

  # Apply a previously generated plan
  deputy fix --plan plan.json --apply .

  # Fix only critical vulnerabilities
  deputy fix --ignore-unfixed

AI ASSISTANCE:
  # Use AI to fix complex issues
  deputy fix --agent codex --agent-model gpt-4

  # Run AI in full-auto mode (dangerous!)
  deputy fix --agent codex --agent-full-auto`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFixPlan(scanner, cmd, args)
		},
	}
	fixCmd.Flags().String("report", "", "Path to JSON output from 'deputy scan --format json'; omit to run a fresh scan (use '-' for stdin)")
	fixCmd.Flags().String("plan", "", "Path to remediation plan JSON (produced via 'deputy fix --format json'); use '-' for stdin")
	fixCmd.Flags().String("ref", "", "Git ref/commit to scan (defaults to HEAD or WORKING when inside a repo)")
	fixCmd.Flags().StringSlice("ecosystems", nil, "Limit scanning to ecosystems: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	fixCmd.Flags().Bool("ignore-unfixed", false, "Ignore vulnerabilities without fixes when generating commands")
	fixCmd.Flags().String("published-before", "", "Only include vulnerabilities published before this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	fixCmd.Flags().String("published-after", "", "Only include vulnerabilities published on/after this date (YYYY, YYYY-MM, YYYY-MM-DD, or RFC3339)")
	fixCmd.Flags().String("as-of", "", "Historical view: show vulnerabilities known up to and including this date (implies --published-before)")
	fixCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
	fixCmd.Flags().String("agent", "", "Use an AI agent to apply fixes (e.g. 'codex')")
	fixCmd.Flags().String("agent-model", "", "Model identifier to use when --agent is set")
	fixCmd.Flags().String("agent-sandbox", "workspace-write", "Sandbox policy for AI agent (read-only|workspace-write|danger-full-access)")
	fixCmd.Flags().Bool("agent-full-auto", false, "Enable codex --full-auto mode")
	fixCmd.Flags().String("agent-thread", "", "Resume a previous codex thread ID")
	fixCmd.Flags().Bool("agent-include-plan-tool", true, "Allow codex agent to enable the plan tool")
	fixCmd.Flags().Bool("agent-skip-git-check", true, "Skip codex git repository checks")
	fixCmd.Flags().Bool("apply", false, "Execute runnable remediation commands in-place (local scans only)")
	fixCmd.Flags().StringArray("policy", nil, "Path to CEL policy files or bundles to evaluate against remediation plans (repeatable)")
	root.AddCommand(fixCmd)
}

// runFixPlan executes the fix command logic. It handles plan generation from
// reports, existing plans, or fresh scans, and optionally applies fixes or
// invokes AI agents.
func runFixPlan(scanner *Scanner, cmd *cobra.Command, args []string) error {
	ctx, span := otel.StartSpan(cmd.Context(), "deputy.fix",
		trace.WithAttributes(
			attribute.String("deputy.command", "fix"),
		))
	defer span.End()
	cmd.SetContext(ctx)

	reportPath, _ := cmd.Flags().GetString("report")
	planPath, _ := cmd.Flags().GetString("plan")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	apply, _ := cmd.Flags().GetBool("apply")
	agentName, agentOpts := getAgentFlags(cmd)
	policyPaths, _ := cmd.Flags().GetStringArray("policy")

	span.SetAttributes(
		attribute.Bool("deputy.fix.apply", apply),
		attribute.Bool("deputy.fix.ignore_unfixed", ignoreUnfixed),
		attribute.String("deputy.fix.agent", agentName),
	)

	if strings.TrimSpace(reportPath) != "" && strings.TrimSpace(planPath) != "" {
		return fmt.Errorf("--report and --plan cannot be used together")
	}

	repoArg := ""
	if len(args) > 0 {
		repoArg = strings.TrimSpace(args[0])
	}

	var (
		plan        remediationPlan
		applyDir    string
		scannedExec *scan.Execution
	)

	switch {
	case strings.TrimSpace(planPath) != "":
		p, err := readPlanSource(cmd.InOrStdin(), planPath)
		if err != nil {
			return err
		}
		plan = p
		if ignoreUnfixed {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: --ignore-unfixed has no effect when --plan is supplied\n")
		}
	case strings.TrimSpace(reportPath) != "":
		data, err := readReportSource(cmd.InOrStdin(), reportPath)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("report %q is empty", reportPath)
		}
		var result ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse report: %w", err)
		}
		findings, advisories := report.SplitVulnerabilities(result.Vulnerabilities)
		scanResult := scan.Result{
			Findings:   findings,
			Advisories: advisories,
			Stats:      result.Stats,
		}
		if ignoreUnfixed {
			scanResult = scan.FilterUnfixed(scanResult)
		}
		cons := vulnerability.Consolidate(scanResult.Findings, scanResult.Advisories)
		commands, stdlib := remediation.CommandsFromConsolidated(cons)
		plan = buildRemediationPlan(result, commands, stdlib)
	default:
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
		scannedExec = exec
		applyDir = exec.Result.Target.LocalPath
		resultOut := exec.Result
		if ignoreUnfixed {
			resultOut = scan.FilterUnfixed(resultOut)
		}
		cons := vulnerability.Consolidate(resultOut.Findings, resultOut.Advisories)
		commands, stdlib := remediation.CommandsFromConsolidated(cons)
		result := buildScanReport(resultOut)
		plan = buildRemediationPlan(result, commands, stdlib)
	}

	if err := runFixPolicies(cmd.Context(), policyPaths, plan, cmd.ErrOrStderr()); err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		printFixSummary(cmd.OutOrStdout(), plan)
	case FormatJSON:
		if err := outputRemediationPlanJSON(cmd.OutOrStdout(), plan); err != nil {
			return err
		}
	default:
		return flags.UnsupportedFormatError("--format", format, "text|json")
	}

	var repoPathForMutations string
	if apply || strings.TrimSpace(agentName) != "" {
		var err error
		repoPathForMutations, err = resolveRepoPath(applyDir, repoArg)
		if err != nil {
			return err
		}
		if scannedExec != nil && scannedExec.Result.Target.Cloned {
			return fmt.Errorf("mutations are only supported for local repositories (clone detected)")
		}
	}

	if apply {
		if err := applyRemediationCommands(cmd.Context(), repoPathForMutations, plan.Commands, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
			return err
		}
	}

	if strings.TrimSpace(agentName) != "" {
		agentPrompt, err := buildCodexFixPrompt(plan)
		if err != nil {
			return err
		}
		if err := runAgent(cmd.Context(), agentName, agentPrompt, repoPathForMutations, agentOpts, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
			return err
		}
	}

	otel.SetSpanOK(span)
	return nil
}

// readReportSource reads the scan report from the specified path or stdin.
func readReportSource(r io.Reader, path string) ([]byte, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, fmt.Errorf("report path is empty")
	}
	if trimmed == "-" {
		return io.ReadAll(r)
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to read report %q: %w", trimmed, err)
	}
	return data, nil
}

// readPlanSource reads the remediation plan from the specified path or stdin.
func readPlanSource(r io.Reader, path string) (remediationPlan, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return remediationPlan{}, fmt.Errorf("plan path is empty")
	}
	var (
		data []byte
		err  error
	)
	if trimmed == "-" {
		data, err = io.ReadAll(r)
	} else {
		data, err = os.ReadFile(trimmed)
	}
	if err != nil {
		return remediationPlan{}, fmt.Errorf("failed to read plan %q: %w", trimmed, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return remediationPlan{}, fmt.Errorf("plan %q is empty", trimmed)
	}
	var plan remediationPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return remediationPlan{}, fmt.Errorf("failed to parse plan: %w", err)
	}
	refreshRemediationPlanStats(&plan)
	return plan, nil
}

// printFixSummary displays a human-readable summary of the remediation plan.
func printFixSummary(w io.Writer, plan remediationPlan) {
	doc, hasCommands := render.FixSummaryDoc(render.TargetSummary{
		Repo:   plan.Target.Repo,
		Ref:    plan.Target.Ref,
		Commit: plan.Target.Commit,
	}, plan.StdlibUpgrade, plan.Stats.TotalCommands, plan.Stats.RunnableCommands, len(plan.Commands))
	_ = doc.Render(w, output.UIStyles())
	if !hasCommands {
		return
	}
	render.RemediationCommands(w, plan.Commands, "       ", "         ")
}

// buildRemediationPlan constructs a remediation plan from the scan result and generated commands.
func buildRemediationPlan(result ScanResult, commands []remediation.Command, stdlib string) remediationPlan {
	plan := remediationPlan{
		Target: report.Target{
			Repo:   result.Repo,
			Ref:    result.Ref,
			Commit: result.Commit,
		},
		StdlibUpgrade: stdlib,
		Commands:      commands,
	}
	refreshRemediationPlanStats(&plan)
	return plan
}

// outputRemediationPlanJSON writes the remediation plan to the writer in JSON format.
func outputRemediationPlanJSON(w io.Writer, plan remediationPlan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(plan)
}

// refreshRemediationPlanStats updates the summary statistics of the remediation plan.
func refreshRemediationPlanStats(plan *remediationPlan) {
	if plan == nil {
		return
	}
	plan.Stats = remediationPlanSummary{
		TotalCommands:    len(plan.Commands),
		RunnableCommands: countExecutable(plan.Commands),
	}
}

// countExecutable returns the number of executable commands in the list.
func countExecutable(commands []remediation.Command) int {
	count := 0
	for _, cmd := range commands {
		if cmd.Executable {
			count++
		}
	}
	return count
}

// applyRemediationCommands executes the runnable commands in the remediation plan.
// It handles both shell commands (e.g., "go get", "npm install") and deputy-internal
// commands (e.g., "deputy:action:update", "deputy:dockerfile:update").
func applyRemediationCommands(ctx context.Context, repoDir string, commands []remediation.Command, out io.Writer, errW io.Writer) error {
	ran := 0
	for _, rec := range commands {
		if !rec.Executable {
			continue
		}

		// Handle deputy-internal commands (file modifications for Actions/Dockerfiles)
		if remediation.IsDeputyInternalCommand(rec.Command) {
			fmt.Fprintf(out, "%s %s\n", ui.StyleUpgraded.Render("↻"), rec.Command)
			if err := remediation.ApplyDeputyCommand(repoDir, rec.Command); err != nil {
				return fmt.Errorf("deputy command %q failed: %w", rec.Command, err)
			}
			ran++
			continue
		}

		// Handle shell commands
		workDir := repoDir
		if strings.TrimSpace(rec.Path) != "" {
			relDir := filepath.Dir(rec.Path)
			if relDir != "." && relDir != "" {
				workDir = filepath.Join(repoDir, relDir)
			}
		}
		if _, err := os.Stat(workDir); err != nil {
			return fmt.Errorf("cannot apply command %q: %w", rec.Command, err)
		}
		displayDir := relativeOrDot(repoDir, workDir)
		fmt.Fprintf(out, "%s %s %s\n", ui.StyleUpgraded.Render("↻"), rec.Command, ui.StyleDim.Render(fmt.Sprintf("(in %s)", displayDir)))
		execCmd := shellCommand(ctx, rec.Command)
		execCmd.Dir = workDir
		execCmd.Stdout = out
		execCmd.Stderr = errW
		if err := execCmd.Run(); err != nil {
			return fmt.Errorf("command %q failed in %s: %w", rec.Command, displayDir, err)
		}
		ran++
	}
	if ran == 0 {
		fmt.Fprintln(out, ui.StyleDim.Render("No runnable commands in remediation plan."))
	}
	return nil
}

// runFixPolicies evaluates policies against the remediation plan and its steps.
func runFixPolicies(ctx context.Context, policyPaths []string, plan remediationPlan, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	planMap, err := structToMap(plan)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, planMap, "fix", policy.EntrypointFixPlan, errW); err != nil {
		return err
	}
	for idx, step := range plan.Commands {
		stepMap, err := structToMap(step)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"plan":  planMap,
			"step":  stepMap,
			"index": idx,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "fix", policy.EntrypointFixPlanStep, errW); err != nil {
			return err
		}
	}
	return nil
}

// shellCommand creates an exec.Cmd to run a shell command.
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd.exe", "/C", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

// relativeOrDot returns the relative path from base to target, or "." if they are the same.
func relativeOrDot(base, target string) string {
	if rel, err := filepath.Rel(base, target); err == nil && rel != "" {
		if rel == "." {
			return rel
		}
		return rel
	}
	return "."
}

// resolveRepoPath determines the absolute path to the repository.
func resolveRepoPath(existing, repoArg string) (string, error) {
	if strings.TrimSpace(existing) != "" {
		return existing, nil
	}
	path := strings.TrimSpace(repoArg)
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to determine working directory: %w", err)
		}
		path = cwd
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %q: %w", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("repository path %q is not accessible: %w", abs, err)
	}
	return abs, nil
}
