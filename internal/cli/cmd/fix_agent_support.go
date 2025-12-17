package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// agentInvocationOptions holds configuration for running an AI agent.
type agentInvocationOptions struct {
	Model            string
	Sandbox          string
	FullAuto         bool
	ThreadID         string
	IncludePlanTool  bool
	SkipGitRepoCheck bool
}

// getAgentFlags extracts all agent-related flags from the command.
// This consolidates the common pattern of reading agent flags used by
// fix, triage, and other agent-enabled commands.
func getAgentFlags(cmd *cobra.Command) (name string, opts agentInvocationOptions) {
	name, _ = cmd.Flags().GetString("agent")
	opts.Model, _ = cmd.Flags().GetString("agent-model")
	opts.Sandbox, _ = cmd.Flags().GetString("agent-sandbox")
	opts.FullAuto, _ = cmd.Flags().GetBool("agent-full-auto")
	opts.ThreadID, _ = cmd.Flags().GetString("agent-thread")
	opts.IncludePlanTool, _ = cmd.Flags().GetBool("agent-include-plan-tool")
	opts.SkipGitRepoCheck, _ = cmd.Flags().GetBool("agent-skip-git-check")
	return name, opts
}

// runAgent dispatches the remediation task to the specified AI agent.
func runAgent(ctx context.Context, name string, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) error {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" || trimmed == "none" {
		fmt.Fprintln(errW, ui.StyleDim.Render("No agent specified; skipping AI remediation."))
		return nil
	}
	if strings.TrimSpace(prompt) == "" {
		return fmt.Errorf("agent %q requires a non-empty prompt", name)
	}

	switch trimmed {
	case "codex":
		return runCodexAgent(ctx, prompt, repoPath, opts, out, errW)
	case "claude":
		return runClaudeAgent(ctx, prompt, repoPath, opts, out, errW)
	default:
		return fmt.Errorf("unsupported agent %q", name)
	}
}
