package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	fixv1 "github.com/temporalio/deputy/gen/deputy/fix/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	deputyerrors "github.com/temporalio/deputy/internal/errors"
	"github.com/temporalio/deputy/internal/ignore"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/output"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
	remediation "github.com/temporalio/deputy/internal/remediation"
	"github.com/temporalio/deputy/internal/report/render"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/services"
	ui "github.com/temporalio/deputy/internal/ui"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// AddFixCommand registers the fix subcommand with the root command.
// It configures flags for report input, plan input, and AI agent options.
func AddFixCommand(root *cobra.Command, c *services.Clients) {
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
			return runFixPlan(c, cmd, args)
		},
	}
	fixCmd.Flags().String("report", "", "Path to JSON output from 'deputy scan --format json'; omit to run a fresh scan (use '-' for stdin)")
	fixCmd.Flags().String("plan", "", "Path to remediation plan JSON (produced via 'deputy fix --format json'); use '-' for stdin")
	fixCmd.Flags().String("ref", "", "Git ref/commit to scan (defaults to HEAD or WORKING when inside a repo)")
	fixCmd.Flags().StringSlice("ecosystems", nil, "Limit scanning to ecosystems: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, mise, asdf, haskell, r, cpp (default: all)")
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
	fixCmd.Flags().Bool("agent-verbose", false, "Show full command output instead of compact summaries")
	fixCmd.Flags().Bool("apply", false, "Execute runnable remediation commands in-place (local scans only)")
	fixCmd.Flags().StringArray("policy", nil, "Path to CEL policy files or bundles to evaluate against remediation plans (repeatable)")
	addExcludePathFlag(fixCmd)
	fixCmd.Flags().String("ignore-file", "", "Path to ignore rules file (.deputyignore.yaml)")
	root.AddCommand(fixCmd)
}

// runFixPlan executes the fix command logic. It handles plan generation from
// reports, existing plans, or fresh scans, and optionally applies fixes or
// invokes AI agents.
func runFixPlan(c *services.Clients, cmd *cobra.Command, args []string) error {
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
		fixResp   *fixv1.FixResponse
		applyDir  string
		wasCloned bool
	)

	switch {
	case strings.TrimSpace(planPath) != "":
		resp, err := readFixPlanProto(cmd.InOrStdin(), planPath)
		if err != nil {
			return err
		}
		fixResp = resp
		if ignoreUnfixed {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: --ignore-unfixed has no effect when --plan is supplied\n")
		}
	case strings.TrimSpace(reportPath) != "":
		resp, err := buildFixFromReport(cmd, cmd.InOrStdin(), reportPath, ignoreUnfixed)
		if err != nil {
			return err
		}
		fixResp = resp
	default:
		ref, _ := cmd.Flags().GetString("ref")
		ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
		publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
		publishedAfterStr, _ := cmd.Flags().GetString("published-after")
		asOfStr, _ := cmd.Flags().GetString("as-of")
		beforeT, afterT := flags.ParsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)

		// Build scan request
		scanOpts := &scanv1.ScanOptions{
			Ecosystems:   ecos,
			ExcludePaths: excludePathsFromCmd(cmd),
		}
		if !beforeT.IsZero() {
			scanOpts.PublishedBefore = timestamppb.New(beforeT)
		}
		if !afterT.IsZero() {
			scanOpts.PublishedAfter = timestamppb.New(afterT)
		}
		if ref != "" {
			scanOpts.Ref = ref
		}

		// Resolve target
		target := repoArg
		if target == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
			target = cwd
		}

		// Call vulnerability scanner
		resp, err := c.Vulns.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
			Target:  target,
			Options: scanOpts,
		}))
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Convert proto response to internal types
		scanResult := internalproto.ScanningResultFromProto(resp.Msg)
		if scanResult == nil {
			return fmt.Errorf("scan returned empty result")
		}

		applyDir = scanResult.Target.LocalPath
		wasCloned = scanResult.Target.Cloned

		resultOut := applyFixIgnoreRules(cmd, *scanResult, applyDir)
		if ignoreUnfixed {
			resultOut = scanning.FilterUnfixed(resultOut)
		}
		cons := vulnerability.Consolidate(resultOut.Findings, resultOut.Advisories)
		commands, stdlib := remediation.CommandsFromConsolidated(cons)
		commands = remediation.ApplyGuidance(commands, remediation.CLIGuidance())
		fixResp = internalproto.BuildFixResponse(
			internalproto.InventoryTargetToProto(scanResult.Target),
			stdlib,
			commands,
		)
	}

	if err := runFixPoliciesProto(ctx, policyPaths, fixResp, cmd.ErrOrStderr()); err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		renderFixText(cmd.OutOrStdout(), fixResp)
	case FormatJSON:
		if err := outputFixProtoJSON(cmd.OutOrStdout(), fixResp); err != nil {
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
		if wasCloned {
			return fmt.Errorf("mutations are only supported for local repositories (clone detected)")
		}
	}

	if apply {
		commands := internalproto.RemediationCommandsFromProto(fixResp.Commands)
		if err := applyRemediationCommands(cmd.Context(), repoPathForMutations, commands, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
			return err
		}
	}

	if strings.TrimSpace(agentName) != "" {
		agentPrompt, err := buildFixPromptProto(fixResp)
		if err != nil {
			return err
		}
		// Print header before agent execution (consistent with explain/triage)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), ui.StyleHeader.Render("Agent Remediation"))

		result := runAgent(ctx, agentName, agentPrompt, repoPathForMutations, agentOpts, cmd.OutOrStdout(), cmd.ErrOrStderr())

		// Return error with appropriate exit code based on agent result
		if result.HasError() {
			return deputyerrors.WithExitCode(result.Err, result.ExitCode)
		}
		// Even without an error, propagate non-zero exit codes (e.g., partial failures)
		if result.ExitCode != 0 {
			return deputyerrors.WithExitCode(nil, result.ExitCode)
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

// readFixPlanProto reads the remediation plan from the specified path or stdin as proto JSON.
func readFixPlanProto(r io.Reader, path string) (*fixv1.FixResponse, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, fmt.Errorf("plan path is empty")
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
		return nil, fmt.Errorf("failed to read plan %q: %w", trimmed, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("plan %q is empty", trimmed)
	}
	var resp fixv1.FixResponse
	if err := protojson.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w", err)
	}
	// Recalculate stats in case plan was edited
	resp.Stats = &fixv1.RemediationStats{
		TotalCommands:    int32(len(resp.Commands)),
		RunnableCommands: int32(countExecutableProto(resp.Commands)),
	}
	return &resp, nil
}

// buildFixFromReport reads a scan report and builds a fix response.
func buildFixFromReport(cmd *cobra.Command, r io.Reader, reportPath string, ignoreUnfixed bool) (*fixv1.FixResponse, error) {
	data, err := readReportSource(r, reportPath)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("report %q is empty", reportPath)
	}

	// Parse the scan response
	var scanResp scanv1.ScanResponse
	if err := protojson.Unmarshal(data, &scanResp); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	// Convert proto response to internal types for consolidation
	scanResult := internalproto.ScanningResultFromProto(&scanResp)
	if scanResult == nil {
		return nil, fmt.Errorf("scan result is empty")
	}

	// An imported report was filtered by its own target's suppressions when
	// it was produced, and the current working directory has no necessary
	// relationship to that target: auto-discovering .deputyignore.yaml here
	// would let an unrelated repository's rules silently drop remediation
	// commands. Only an explicit --ignore-file applies.
	resultOut := applyFixIgnoreRules(cmd, *scanResult, "")
	if ignoreUnfixed {
		resultOut = scanning.FilterUnfixed(resultOut)
	}
	cons := vulnerability.Consolidate(resultOut.Findings, resultOut.Advisories)
	commands, stdlib := remediation.CommandsFromConsolidated(cons)
	commands = remediation.ApplyGuidance(commands, remediation.CLIGuidance())

	return internalproto.BuildFixResponse(scanResp.Target, stdlib, commands), nil
}

// applyFixIgnoreRules filters findings through the target's vulnerability
// suppressions (--ignore-file, or auto-discovered .deputyignore.yaml and
// friends), matching deputy scan, so the plan never recommends work the
// repository has documented as suppressed. An empty workDir disables
// auto-discovery, leaving only an explicit --ignore-file: imported reports
// have no local target to discover rules from. Load failures degrade to no
// suppressions with a warning.
func applyFixIgnoreRules(cmd *cobra.Command, result scanning.Result, workDir string) scanning.Result {
	ignoreFile, _ := cmd.Flags().GetString("ignore-file")
	var rules *ignore.Rules
	var err error
	switch {
	case ignoreFile != "":
		rules, err = ignore.LoadFromPath(ignoreFile)
	case workDir != "":
		rules, err = ignore.LoadFromDirectory(workDir)
	default:
		return result
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: loading ignore rules: %v\n", err)
		return result
	}
	filtered, ignored := scanning.FilterIgnored(result, rules)
	if ignored > 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "  "+ui.StyleMeta.Render(fmt.Sprintf("Note: %d vulnerability finding(s) ignored by rules", ignored)))
	}
	return filtered
}

// renderFixText displays a human-readable summary of the remediation plan.
func renderFixText(w io.Writer, resp *fixv1.FixResponse) {
	var repo, commit string
	if resp.Target != nil {
		repo = resp.Target.DisplayPath
		commit = resp.Target.CommitHash
	}
	var totalCmds, runnableCmds int32
	if resp.Stats != nil {
		totalCmds = resp.Stats.TotalCommands
		runnableCmds = resp.Stats.RunnableCommands
	}
	doc, hasCommands := render.FixSummaryDoc(render.TargetSummary{
		Repo:   repo,
		Commit: commit,
	}, resp.StdlibUpgrade, int(totalCmds), int(runnableCmds), len(resp.Commands))
	_ = doc.Render(w, output.UIStyles())
	if !hasCommands {
		return
	}
	// Convert proto commands to internal for rendering
	commands := internalproto.RemediationCommandsFromProto(resp.Commands)
	render.RemediationCommands(w, commands, "       ", "         ")
}

// outputFixProtoJSON writes the fix response as JSON using protojson.
func outputFixProtoJSON(w io.Writer, resp *fixv1.FixResponse) error {
	opts := internalproto.CLIJSONMarshalOptions()
	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal proto to JSON: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// countExecutableProto returns the number of executable commands in the proto slice.
func countExecutableProto(commands []*fixv1.RemediationCommand) int {
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
			if err := remediation.ApplyDeputyCommand(ctx, repoDir, rec.Command); err != nil {
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
		args, err := remediation.ExecArgs(rec)
		if err != nil {
			return fmt.Errorf("cannot apply command %q: %w", rec.Command, err)
		}
		execCmd := exec.CommandContext(ctx, args[0], args[1:]...)
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

// runFixPoliciesProto evaluates policies against the proto fix response.
func runFixPoliciesProto(ctx context.Context, policyPaths []string, resp *fixv1.FixResponse, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	// Pass proto message directly to CEL
	payload := map[string]any{
		"plan":   resp,
		"target": resp.Target,
		"stats":  resp.Stats,
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "fix", policy.EntrypointFixPlan, errW); err != nil {
		return err
	}
	for idx, step := range resp.Commands {
		stepPayload := map[string]any{
			"plan":  resp,
			"step":  step,
			"index": idx,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, stepPayload, "fix", policy.EntrypointFixPlanStep, errW); err != nil {
			return err
		}
	}
	return nil
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
