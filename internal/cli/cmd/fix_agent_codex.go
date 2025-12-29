package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/picatz/deputy/internal/report"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/openai/codex"
)

// runCodexAgent initializes and runs the Codex agent for remediation.
// It configures the sandbox mode, sets up the arguments, and streams events to the output.
func runCodexAgent(ctx context.Context, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) error {
	if strings.TrimSpace(repoPath) == "" {
		return fmt.Errorf("--agent codex requires a local repository path (pass it as an argument or run from the repo root)")
	}

	sandboxMode, err := parseCodexSandbox(opts.Sandbox)
	if err != nil {
		return err
	}

	args := codex.Args{
		Input:            prompt,
		Model:            opts.Model,
		SandboxMode:      sandboxMode,
		WorkingDirectory: repoPath,
		SkipGitRepoCheck: opts.SkipGitRepoCheck,
		ThreadID:         opts.ThreadID,
		FullAuto:         opts.FullAuto,
		IncludePlanTool:  opts.IncludePlanTool,
	}

	slog.Info("codex agent starting", "repo", repoPath, "sandbox", sandboxMode, "thread", opts.ThreadID)
	fmt.Fprintf(out, "%s Starting codex agent in %s (sandbox=%s)\n", ui.StyleManager.Render("codex"), ui.StylePath.Render(repoPath), sandboxMode)

	for event, evtErr := range codex.Run(ctx, args) {
		if evtErr != nil {
			return evtErr
		}
		renderCodexEvent(out, event)
	}

	fmt.Fprintln(out, ui.StyleUpgraded.Render("codex remediation completed."))
	return nil
}

// buildCodexFixPrompt constructs the prompt for the Codex agent based on the remediation plan.
func buildCodexFixPrompt(plan remediationPlan) (string, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode plan: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("You are Deputy's remediation agent.\n")
	sb.WriteString("Follow the remediation plan JSON provided below to fix the repository.\n")
	sb.WriteString("For each command marked executable=true, run it in the shell when appropriate.\n")
	sb.WriteString("For commands marked executable=false, edit the referenced files accordingly.\n")
	sb.WriteString("After applying changes, run relevant tests (e.g., 'go test ./...' or language-specific equivalents) when feasible.\n")
	sb.WriteString("Prefer minimal, targeted edits that satisfy the plan.\n")
	sb.WriteString("Summarize your work at the end.\n\n")
	sb.WriteString("Remediation Plan JSON:\n")
	sb.Write(data)
	sb.WriteString("\n")
	return sb.String(), nil
}

// buildCodexTriagePrompt constructs the prompt for the Codex agent based on the triage report.
func buildCodexTriagePrompt(triageReport report.TriageReport) (string, error) {
	data, err := json.MarshalIndent(triageReport, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode triage report: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("You are Deputy's security triage assistant.\n")
	sb.WriteString("Review the vulnerability summary JSON below, identify the issues that pose the highest risk to production systems, and explain why.\n")
	sb.WriteString("Focus on exploitability, blast radius, and upgrade complexity.\n")
	sb.WriteString("Suggest concrete remediation steps (including code areas to inspect) and any validation or regression tests engineers should run.\n")
	sb.WriteString("Format your response with sections: 'Prioritized Risks', 'Recommended Actions', and 'Suggested Tests'.\n\n")
	sb.WriteString("Triage Report JSON:\n")
	sb.Write(data)
	sb.WriteString("\n")
	return sb.String(), nil
}

// parseCodexSandbox converts the sandbox string to a codex.SandboxMode.
func parseCodexSandbox(value string) (codex.SandboxMode, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "", "workspace-write":
		return codex.SandboxModeWorkspaceWrite, nil
	case "read-only":
		return codex.SandboxModeReadOnly, nil
	case "danger-full-access":
		return codex.SandboxModeDangerFullAccess, nil
	default:
		return "", fmt.Errorf("unknown agent sandbox %q", value)
	}
}

// renderCodexEvent formats and prints Codex agent events to the output writer.
func renderCodexEvent(out io.Writer, event *codex.ThreadEvent) {
	if event == nil {
		return
	}

	switch item := event.Item.(type) {
	case *codex.AgentMessageItem:
		text := strings.TrimSpace(item.Text)
		if text != "" {
			fmt.Fprintf(out, "%s %s\n", ui.StyleManager.Render("codex"), text)
			return
		}
	case *codex.ReasoningItem:
		txt := strings.TrimSpace(item.Text)
		if txt != "" {
			fmt.Fprintf(out, "%s %s\n", ui.StyleDim.Render("reasoning:"), txt)
			return
		}
	case *codex.CommandExecutionItem:
		status := string(item.Status)
		if item.ExitCode != nil {
			status = fmt.Sprintf("%s (exit %d)", status, *item.ExitCode)
		}
		fmt.Fprintf(out, "%s %s %s\n", ui.StyleManager.Render("$"), ui.StylePackageName.Render(item.Command), ui.StyleDim.Render(status))
		if strings.TrimSpace(item.AggregatedOutput) != "" {
			fmt.Fprintf(out, "%s\n", strings.TrimSpace(item.AggregatedOutput))
		}
		return
	case *codex.FileChangeItem:
		for _, change := range item.Changes {
			fmt.Fprintf(out, "%s %s %s\n", ui.StylePath.Render(change.Path), ui.StyleVersion.Render(string(change.Kind)), ui.StyleDim.Render(string(item.Status)))
		}
		return
	case *codex.ErrorItem:
		fmt.Fprintf(out, "%s %s\n", ui.StyleRemoved.Render("error:"), strings.TrimSpace(item.Message))
		return
	}

	switch event.Type {
	case codex.EventTypeTurnFailed:
		if event.Error != nil {
			fmt.Fprintf(out, "%s %s\n", ui.StyleRemoved.Render("codex failed:"), event.Error.Message)
			return
		}
	}

	fmt.Fprintf(out, "%s %s\n", ui.StyleDim.Render("codex"), event.String())
}
