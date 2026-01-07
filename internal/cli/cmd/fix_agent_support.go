package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/ai/render"
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
// It uses the ai package's provider registry to find and run the appropriate provider.
func runAgent(ctx context.Context, name string, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) error {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" || trimmed == "none" {
		fmt.Fprintln(errW, ui.StyleDim.Render("No agent specified; skipping AI remediation."))
		return nil
	}
	if strings.TrimSpace(prompt) == "" {
		return fmt.Errorf("agent %q requires a non-empty prompt", name)
	}

	// Get the provider from the unified ai package registry
	provider, err := ai.GetProvider(trimmed)
	if err != nil {
		available := ai.ListProviders()
		if len(available) > 0 {
			return fmt.Errorf("unsupported agent %q (available: %s)", name, strings.Join(available, ", "))
		}
		return fmt.Errorf("unsupported agent %q; no providers registered", name)
	}

	return runAIProvider(ctx, provider, prompt, repoPath, opts, out, errW)
}

// runAIProvider executes an AI provider from the ai package.
func runAIProvider(ctx context.Context, provider ai.Provider, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) error {
	caps := provider.Capabilities()
	name := provider.Name()

	// Validate that the provider supports agentic execution
	if !caps.Agentic {
		fmt.Fprintf(errW, "Warning: provider %q does not support agentic execution; results may be limited to suggestions\n", name)
	}

	// Parse sandbox mode
	sandbox := parseSandbox(opts.Sandbox)

	// Configure approval policy based on FullAuto flag
	var approval *ai.ApprovalPolicy
	if opts.FullAuto {
		// Full auto mode: auto-approve everything (dangerous!)
		fmt.Fprintf(errW, "%s Full-auto mode enabled: commands and file writes will execute without approval\n",
			ui.StyleRemoved.Render("WARNING:"))
		approval = ai.AutoApprovePolicy()
	} else {
		// Default: require approval with interactive approver
		approval = &ai.ApprovalPolicy{
			Commands:       ai.ApprovalRequired,
			FileWrites:     ai.ApprovalRequired,
			HighRiskAlways: true,
			Approver:       createInteractiveApprover(out, errW),
		}
	}

	// Create a session for stateful interaction with hooks
	session := ai.NewSession(ai.SessionConfig{
		Provider:  provider,
		Model:     opts.Model,
		WorkDir:   repoPath,
		Sandbox:   sandbox,
		SessionID: opts.ThreadID,
		Approval:  approval,
		Hooks: ai.SessionHooks{
			OnCommand: func(cmd string) error {
				// Log command execution (approval already happened)
				fmt.Fprintf(out, "%s %s\n", ui.StyleManager.Render("$"), ui.StylePackageName.Render(cmd))
				return nil
			},
			OnFileWrite: func(path string) error {
				// Log file write (approval already happened)
				fmt.Fprintf(out, "%s %s\n", ui.StylePath.Render("[modify]"), path)
				return nil
			},
		},
	})


	// Create streaming renderer with spinner support
	renderer := render.NewStreamingRenderer(out, errW, name)
	renderer.StartSpinner(ctx, "Waiting for agent")

	// Stream the response, rendering events as they occur
	for event, err := range session.Stream(ctx, prompt) {
		if err != nil {
			renderer.Fail()
			fmt.Fprintf(errW, "%s %v\n", ui.StyleRemoved.Render("error:"), err)
			continue
		}
		renderer.RenderEvent(event)
	}

	return nil
}

// createInteractiveApprover creates an approval function that prompts the user.
// In a real CLI, this would use a proper interactive prompt (e.g., survey, bubbletea).
// For now, it auto-approves but logs the operation for visibility.
func createInteractiveApprover(out, errW io.Writer) ai.ApprovalFunc {
	return func(op ai.ApprovalOperation) error {
		// Show the operation to the user
		marker := ui.StyleDim.Render("[approval]")
		if op.HighRisk {
			marker = ui.StyleRemoved.Render("[HIGH-RISK]")
		}

		fmt.Fprintf(out, "%s %s: %s\n", marker, op.Type, op.Description)

		// For now, auto-approve non-high-risk operations
		// TODO: Implement proper interactive approval (e.g., "Press y to approve")
		if op.HighRisk {
			fmt.Fprintf(errW, "%s High-risk operation requires explicit approval (use --agent-full-auto to skip)\n",
				ui.StyleRemoved.Render("BLOCKED:"))
			return fmt.Errorf("high-risk operation blocked: %s", op.Description)
		}

		return nil // Auto-approve non-high-risk
	}
}

// parseSandbox converts the sandbox string to an ai.Sandbox value.
func parseSandbox(value string) ai.Sandbox {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "", "workspace-write":
		return ai.SandboxWorkspaceWrite
	case "read-only":
		return ai.SandboxReadOnly
	case "danger-full-access", "full-access":
		return ai.SandboxFullAccess
	default:
		return ai.SandboxWorkspaceWrite
	}
}

// runAgentAnalysis runs an agent for read-only analysis tasks (like triage).
// Unlike runAgent, this collects the full response and renders it with glamour
// for beautiful markdown output - no real-time streaming of commands/files.
func runAgentAnalysis(ctx context.Context, name string, prompt string, repoPath string, opts agentInvocationOptions, out io.Writer) error {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" || trimmed == "none" {
		return nil
	}
	if strings.TrimSpace(prompt) == "" {
		return fmt.Errorf("agent %q requires a non-empty prompt", name)
	}

	// Get the provider from the registry
	provider, err := ai.GetProvider(trimmed)
	if err != nil {
		available := ai.ListProviders()
		if len(available) > 0 {
			return fmt.Errorf("agent %q not available (available: %s)", name, strings.Join(available, ", "))
		}
		return fmt.Errorf("agent %q not available; install claude or codex CLI", name)
	}

	// Parse sandbox mode
	sandbox := parseSandbox(opts.Sandbox)

	// Use the shared render.StreamResponse for consistent glamour output
	return render.StreamResponse(ctx, provider, &ai.CompletionRequest{
		Prompt:    prompt,
		Model:     opts.Model,
		MaxTokens: 4096,
		Sandbox:   sandbox,
		WorkDir:   repoPath,
	}, render.Config{
		Out:            out,
		Err:            os.Stderr,
		SpinnerMessage: trimmed,
		ProviderName:   trimmed,
		Model:          opts.Model,
		RenderMarkdown: true,
		ShowMetadata:   true,
		WordWrap:       80,
	})
}
