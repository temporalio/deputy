package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/spf13/cobra"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	triagev1 "github.com/temporalio/deputy/gen/deputy/triage/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/report"
	"github.com/temporalio/deputy/internal/report/render"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/services"
	ui "github.com/temporalio/deputy/internal/ui"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// AddTriageCommand registers the triage subcommand.
func AddTriageCommand(root *cobra.Command, c *services.Clients) {
	triageCmd := &cobra.Command{
		Use:           "triage [repo]",
		Aliases:       []string{"t", "tri"},
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
			return runTriage(c, cmd, args)
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
func runTriage(c *services.Clients, cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
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
		triageResp *triagev1.TriageResponse
		repoPath   string
	)

	if strings.TrimSpace(reportPath) != "" {
		data, err := readReportSource(cmd.InOrStdin(), reportPath)
		if err != nil {
			return err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return fmt.Errorf("report %q is empty", reportPath)
		}
		// Parse proto JSON format from scan command output
		var scanResp scanv1.ScanResponse
		if err := protojson.Unmarshal(data, &scanResp); err != nil {
			return fmt.Errorf("failed to parse report: %w", err)
		}
		// Convert proto to internal types for processing
		scanResult := internalproto.ScanningResultFromProto(&scanResp)
		if scanResult == nil {
			return fmt.Errorf("failed to convert scan response")
		}
		if ignoreUnfixed {
			*scanResult = scanning.FilterUnfixed(*scanResult)
		}
		cons := vulnerability.Consolidate(scanResult.Findings, scanResult.Advisories)
		displayPath := ""
		commit := ""
		if scanResp.Target != nil {
			displayPath = scanResp.Target.DisplayPath
			commit = scanResp.Target.CommitHash
		}
		triageResp = internalproto.BuildTriageResponse(displayPath, scanResult.Stats, cons, 10)
		triageResp.Target = &targetv1.Target{
			DisplayPath: displayPath,
			CommitHash:  commit,
		}
	} else {
		ref, _ := cmd.Flags().GetString("ref")
		ecos, _ := cmd.Flags().GetStringSlice("ecosystems")
		publishedBeforeStr, _ := cmd.Flags().GetString("published-before")
		publishedAfterStr, _ := cmd.Flags().GetString("published-after")
		asOfStr, _ := cmd.Flags().GetString("as-of")
		beforeT, afterT := flags.ParsePublishedFilters(cmd.ErrOrStderr(), asOfStr, publishedBeforeStr, publishedAfterStr)

		// Build scan request
		scanOpts := &scanv1.ScanOptions{
			Ecosystems: ecos,
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

		// Convert proto response to internal types for consolidation
		scanResult := internalproto.ScanningResultFromProto(resp.Msg)
		if scanResult == nil {
			return fmt.Errorf("scan returned empty result")
		}

		for _, warning := range scanResult.Warnings {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
		}

		repoPath = scanResult.Target.LocalPath
		resultOut := *scanResult
		if ignoreUnfixed {
			resultOut = scanning.FilterUnfixed(resultOut)
		}
		cons := vulnerability.Consolidate(resultOut.Findings, resultOut.Advisories)
		triageResp = internalproto.BuildTriageResponse(scanResult.Target.DisplayPath, resultOut.Stats, cons, 10)
		triageResp.Target = &targetv1.Target{
			DisplayPath: scanResult.Target.DisplayPath,
			LocalPath:   scanResult.Target.LocalPath,
			CommitHash:  scanResult.Target.CommitHash,
		}
	}

	if err := runTriagePoliciesProto(ctx, policyPaths, triageResp, cmd.ErrOrStderr()); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		renderTriageText(cmd.OutOrStdout(), triageResp, showDBInfo)
	case FormatJSON:
		if err := outputTriageProtoJSON(cmd.OutOrStdout(), triageResp); err != nil {
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
		prompt, err := buildTriagePromptProto(triageResp)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), ui.StyleHeader.Render("Agent Analysis"))
		if err := runAgentAnalysis(ctx, agentName, prompt, targetRepo, agentOpts, cmd.OutOrStdout()); err != nil {
			return err
		}
	}

	return nil
}

// runTriagePoliciesProto evaluates policies against the proto triage response.
func runTriagePoliciesProto(ctx context.Context, policyPaths []string, triageResp *triagev1.TriageResponse, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	// Pass proto message directly to CEL
	reportPayload := map[string]any{
		"report":       triageResp,
		"target":       triageResp.Target,
		"stats":        triageResp.Stats,
		"top_packages": triageResp.TopPackages,
	}
	if _, err := evaluatePoliciesForCommand(ctx, policyPaths, reportPayload, "triage", policy.EntrypointTriageReport, errW); err != nil {
		return err
	}
	// Evaluate per-cluster policies
	for _, pkg := range triageResp.TopPackages {
		clusterPayload := map[string]any{
			"target":  triageResp.Target,
			"cluster": pkg,
		}
		if _, err := evaluatePoliciesForCommand(ctx, policyPaths, clusterPayload, "triage", policy.EntrypointTriageCluster, errW); err != nil {
			return err
		}
	}
	return nil
}

// outputTriageProtoJSON writes the triage response as JSON using protojson.
func outputTriageProtoJSON(w io.Writer, resp *triagev1.TriageResponse) error {
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
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

// renderTriageText outputs the triage response as human-readable text.
func renderTriageText(w io.Writer, resp *triagev1.TriageResponse, showDBInfo bool) {
	// Convert proto to the render format
	triageReport := report.TriageReport{
		Stats:             resp.Stats,
		PackagesWithVulns: int(resp.PackagesWithVulns),
	}
	if resp.Target != nil {
		triageReport.Target = report.Target{
			Repo:   resp.Target.DisplayPath,
			Commit: resp.Target.CommitHash,
		}
	}
	for _, pkg := range resp.TopPackages {
		summary := report.TriagePackageSummary{
			Package:            pkg.Package,
			Version:            pkg.Version,
			Severity:           pkg.Severity,
			SeverityType:       pkg.SeverityType,
			FixVersion:         pkg.FixVersion,
			IsDirect:           pkg.IsDirect,
			Summary:            pkg.Summary,
			SampleIDs:          pkg.SampleIds,
			DatabaseSpecific:   pkg.DatabaseSpecific,
			VulnerabilityCount: int(pkg.VulnerabilityCount),
		}
		if len(pkg.AffectedImports) > 0 {
			for _, imp := range pkg.AffectedImports {
				if imp == nil {
					continue
				}
				summary.AffectedImports = append(summary.AffectedImports, vulnerabilityv1.AffectedImport{
					Path:    imp.Path,
					Symbols: slices.Clone(imp.Symbols),
				})
			}
		}
		if pkg.SeverityCounts != nil {
			summary.SeverityCounts = make(map[string]int)
			for k, v := range pkg.SeverityCounts {
				summary.SeverityCounts[k] = int(v)
			}
		}
		triageReport.TopPackages = append(triageReport.TopPackages, summary)
	}
	render.TriageSummary(w, triageReport, showDBInfo)
}

// buildTriagePromptProto creates a prompt for the AI agent from the proto triage response.
func buildTriagePromptProto(resp *triagev1.TriageResponse) (string, error) {
	// Use protojson for consistent formatting
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	data, err := opts.Marshal(resp)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`Analyze this vulnerability triage report and provide prioritized recommendations:

%s

Focus on:
1. Which vulnerabilities should be addressed first and why
2. Potential exploit paths or attack vectors
3. Quick wins (easy fixes with high impact)
4. Any patterns or systemic issues`, string(data)), nil
}
