package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	ui "github.com/picatz/deputy/internal/ui"
)

type agentInvocationOptions struct {
	Model            string
	Sandbox          string
	FullAuto         bool
	ThreadID         string
	IncludePlanTool  bool
	SkipGitRepoCheck bool
}

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
