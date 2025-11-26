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

	inv "github.com/picatz/deputy/internal/inventory"
	remediation "github.com/picatz/deputy/internal/remediation"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

type remediationPlan struct {
	Target        remediationPlanTarget  `json:"target"`
	StdlibUpgrade string                 `json:"stdlibUpgrade,omitempty"`
	Commands      []remediation.Command  `json:"commands"`
	Stats         remediationPlanSummary `json:"stats"`
}

type remediationPlanTarget struct {
	Repo   string `json:"repo"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
}

type remediationPlanSummary struct {
	TotalCommands    int `json:"totalCommands"`
	RunnableCommands int `json:"runnableCommands"`
}

func AddFixCommand(root *cobra.Command) {
	scanner := NewScanner()
	fixCmd := &cobra.Command{
		Use:   "fix [repo]",
		Short: "Generate and optionally apply remediation steps",
		Long: `Run a scan (or consume an existing JSON report) and produce actionable
remediation commands. When run without --report, the fix command performs the
same multi-ecosystem inventory scan as "deputy scan" before building the plan.`,
		Example: `SCAN CURRENT REPOSITORY:
	  deputy fix

REPLAY REMOTE / REPORT RESULTS:
	  deputy fix github.com/hashicorp/vagrant --ignore-unfixed
	  deputy scan --format json --output scan.json
	  deputy fix --report scan.json

PIPE A REPORT DIRECTLY:
	  deputy scan --format json --output - | deputy fix --report -

USE A SAVED REMEDIATION PLAN:
	  deputy fix --plan plan.json
	  deputy fix --plan plan.json --apply .

AI-ASSISTED REMEDIATION:
	  deputy fix --plan plan.json --agent codex --agent-model gpt-4.1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFixPlan(scanner, cmd, args)
		},
	}
	fixCmd.Flags().String("report", "", "Path to JSON output from 'deputy scan --format json'; omit to run a fresh scan (use '-' for stdin)")
	fixCmd.Flags().String("plan", "", "Path to remediation plan JSON (produced via 'deputy fix --format json'); use '-' for stdin")
	fixCmd.Flags().String("ref", "", "Git ref/commit to scan (defaults to HEAD or WORKING when inside a repo)")
	fixCmd.Flags().StringSlice("ecosystems", nil, "Limit scanning to specific ecosystems (defaults to all supported)")
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

func runFixPlan(scanner *Scanner, cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")
	planPath, _ := cmd.Flags().GetString("plan")
	ignoreUnfixed, _ := cmd.Flags().GetBool("ignore-unfixed")
	apply, _ := cmd.Flags().GetBool("apply")
	agentName, _ := cmd.Flags().GetString("agent")
	agentModel, _ := cmd.Flags().GetString("agent-model")
	agentSandbox, _ := cmd.Flags().GetString("agent-sandbox")
	agentFullAuto, _ := cmd.Flags().GetBool("agent-full-auto")
	agentThreadID, _ := cmd.Flags().GetString("agent-thread")
	agentIncludePlanTool, _ := cmd.Flags().GetBool("agent-include-plan-tool")
	agentSkipGitCheck, _ := cmd.Flags().GetBool("agent-skip-git-check")
	policyPaths, _ := cmd.Flags().GetStringArray("policy")

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
		scannedExec *scanExecution
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
		if ignoreUnfixed {
			result.Vulnerabilities = filterUnfixed(result.Vulnerabilities)
		}
		commands, stdlib := remediation.CommandsFromVulnerabilities(result.Vulnerabilities)
		plan = buildRemediationPlan(result, commands, stdlib)
	default:
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
		scannedExec = exec
		applyDir = exec.localRepoPath
		vulns := exec.vulnerabilities
		if ignoreUnfixed {
			vulns = filterUnfixed(vulns)
		}
		result := buildScanReport(exec.displayPath, ref, exec.commitHash, vulns, len(exec.packages))
		commands, stdlib := remediation.CommandsFromVulnerabilities(result.Vulnerabilities)
		plan = buildRemediationPlan(result, commands, stdlib)
	}

	if err := runFixPolicies(cmd.Context(), policyPaths, plan, cmd.ErrOrStderr()); err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		printFixSummary(plan)
	case "json":
		if err := outputRemediationPlanJSON(cmd.OutOrStdout(), plan); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported --format %q (use text|json)", format)
	}

	var repoPathForMutations string
	if apply || strings.TrimSpace(agentName) != "" {
		var err error
		repoPathForMutations, err = resolveRepoPath(applyDir, repoArg)
		if err != nil {
			return err
		}
		if scannedExec != nil && scannedExec.cloned {
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
		agentOpts := agentInvocationOptions{
			Model:            agentModel,
			Sandbox:          agentSandbox,
			FullAuto:         agentFullAuto,
			ThreadID:         agentThreadID,
			IncludePlanTool:  agentIncludePlanTool,
			SkipGitRepoCheck: agentSkipGitCheck,
		}
		if err := runAgent(cmd.Context(), agentName, agentPrompt, repoPathForMutations, agentOpts, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
			return err
		}
	}

	return nil
}

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

func printFixSummary(plan remediationPlan) {
	fmt.Println(ui.StyleHeader.Render("Remediation Plan:"))
	if repo := strings.TrimSpace(plan.Target.Repo); repo != "" {
		repoLine := repo
		if plan.Target.Ref != "" {
			repoLine = fmt.Sprintf("%s@%s", repoLine, plan.Target.Ref)
		}
		fmt.Println("  Target:", ui.StylePackageName.Render(repoLine))
	}
	if plan.Target.Commit != "" {
		fmt.Println("  Commit:", ui.StyleVersion.Render(plan.Target.Commit))
	}
	if plan.StdlibUpgrade != "" {
		fmt.Printf("  • %s %s %s\n", ui.StyleBold.Render("Upgrade Go toolchain to"), ui.StyleUpgraded.Render(plan.StdlibUpgrade), ui.StyleVersion.Render("(update 'go' directive in go.mod)"))
	}
	if len(plan.Commands) == 0 {
		fmt.Println("  • No dependency upgrades with fixes (report contains only unfixed issues).")
		return
	}
	fmt.Printf("  • %s (%d total, %d runnable)\n", ui.StyleBold.Render("Apply dependency upgrades"), plan.Stats.TotalCommands, plan.Stats.RunnableCommands)
	renderRemediationCommands(plan.Commands, "       ", "         ")
}

func buildRemediationPlan(result ScanResult, commands []remediation.Command, stdlib string) remediationPlan {
	plan := remediationPlan{
		Target: remediationPlanTarget{
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

func outputRemediationPlanJSON(w io.Writer, plan remediationPlan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(plan)
}

func refreshRemediationPlanStats(plan *remediationPlan) {
	if plan == nil {
		return
	}
	plan.Stats = remediationPlanSummary{
		TotalCommands:    len(plan.Commands),
		RunnableCommands: countExecutable(plan.Commands),
	}
}

func countExecutable(commands []remediation.Command) int {
	count := 0
	for _, cmd := range commands {
		if cmd.Executable {
			count++
		}
	}
	return count
}

func applyRemediationCommands(ctx context.Context, repoDir string, commands []remediation.Command, out io.Writer, errW io.Writer) error {
	ran := 0
	for _, rec := range commands {
		if !rec.Executable {
			continue
		}
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

func runFixPolicies(ctx context.Context, policyPaths []string, plan remediationPlan, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	planMap, err := structToMap(plan)
	if err != nil {
		return err
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, planMap, "fix", "fix_plan", errW); err != nil {
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
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, payload, "fix", "fix_plan_step", errW); err != nil {
			return err
		}
	}
	return nil
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd.exe", "/C", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func relativeOrDot(base, target string) string {
	if rel, err := filepath.Rel(base, target); err == nil && rel != "" {
		if rel == "." {
			return rel
		}
		return rel
	}
	return "."
}

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
