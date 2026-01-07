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
	Verbose          bool // Show full command output instead of compact summaries
}

// AgentResult captures the outcome of an agent execution.
type AgentResult struct {
	// Status is the overall outcome (success, partial, failed, interrupted).
	Status render.AgentStatus
	// ExitCode is the suggested process exit code (0=success, 1=failure, 130=interrupted).
	ExitCode int
	// Err is any error that occurred during execution.
	Err error
}

// Error implements the error interface, returning the underlying error message.
func (r AgentResult) Error() string {
	if r.Err != nil {
		return r.Err.Error()
	}
	return ""
}

// HasError returns true if the result contains an error.
func (r AgentResult) HasError() bool {
	return r.Err != nil
}

// Success returns true if the agent completed successfully (exit code 0).
func (r AgentResult) Success() bool {
	return r.ExitCode == 0 && r.Err == nil
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
	opts.Verbose, _ = cmd.Flags().GetBool("agent-verbose")
	return name, opts
}

// runAgent dispatches the remediation task to the specified AI agent.
// It uses the ai package's provider registry to find and run the appropriate provider.
// Returns an AgentResult with the outcome status and exit code for the caller to use.
func runAgent(ctx context.Context, name string, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) AgentResult {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" || trimmed == "none" {
		fmt.Fprintln(errW, ui.StyleDim.Render("No agent specified; skipping AI remediation."))
		return AgentResult{Status: render.AgentStatusSuccess, ExitCode: 0}
	}
	if strings.TrimSpace(prompt) == "" {
		return AgentResult{
			Status:   render.AgentStatusFailed,
			ExitCode: 1,
			Err:      fmt.Errorf("agent %q requires a non-empty prompt", name),
		}
	}

	// Get the provider from the unified ai package registry
	provider, err := ai.GetProvider(trimmed)
	if err != nil {
		available := ai.ListProviders()
		if len(available) > 0 {
			return AgentResult{
				Status:   render.AgentStatusFailed,
				ExitCode: 1,
				Err:      fmt.Errorf("unsupported agent %q (available: %s)", name, strings.Join(available, ", ")),
			}
		}
		return AgentResult{
			Status:   render.AgentStatusFailed,
			ExitCode: 1,
			Err:      fmt.Errorf("unsupported agent %q; no providers registered", name),
		}
	}

	return runAIProvider(ctx, provider, prompt, repoPath, opts, out, errW)
}

// runAIProvider executes an AI provider from the ai package.
// Returns an AgentResult with the renderer's status and exit code.
func runAIProvider(ctx context.Context, provider ai.Provider, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) AgentResult {
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
				// Note: This is now handled by the StreamingRenderer
				return nil
			},
			OnFileWrite: func(path string) error {
				// Log file write (approval already happened)
				// Note: This is now handled by the StreamingRenderer
				return nil
			},
		},
	})

	// Create streaming renderer with full configuration for metadata footer
	renderer := render.NewStreamingRendererWithConfig(render.StreamingConfig{
		Out:          out,
		Err:          errW,
		ProviderName: name,
		Model:        opts.Model,
		Sandbox:      sandbox,
		ShowMetadata: true,
		Verbose:      opts.Verbose,
	})
	renderer.StartSpinner(ctx, name)

	// Stream the response, rendering events as they occur
	var streamErr error
	for event, err := range session.Stream(ctx, prompt) {
		if err != nil {
			// Check if it's just a context cancellation (CTRL+C)
			if ctx.Err() != nil {
				renderer.Clear()
				break
			}
			renderer.Fail()
			streamErr = err
			continue
		}
		renderer.RenderEvent(event)
	}

	// Show metadata footer with timing and token usage
	renderer.Finish(true)

	// Return result with status from renderer (reflects command success/failure)
	return AgentResult{
		Status:   renderer.Status(),
		ExitCode: renderer.ExitCode(),
		Err:      streamErr,
	}
}

// createInteractiveApprover creates an approval function that prompts the user.
// In a real CLI, this would use a proper interactive prompt (e.g., survey, bubbletea).
// For now, it silently auto-approves non-high-risk operations - the command events
// themselves will be displayed by the StreamingRenderer when they complete.
func createInteractiveApprover(out, errW io.Writer) ai.ApprovalFunc {
	return func(op ai.ApprovalOperation) error {
		// Block high-risk operations unless full-auto mode is enabled
		if op.HighRisk {
			fmt.Fprintf(errW, "\n%s High-risk operation requires explicit approval\n",
				ui.StyleRemoved.Render("BLOCKED:"))
			fmt.Fprintf(errW, "  %s: %s\n", op.Type, op.Description)
			fmt.Fprintf(errW, "  Use --agent-full-auto to allow all operations\n")
			return fmt.Errorf("high-risk operation blocked: %s", op.Description)
		}

		// Silently auto-approve non-high-risk operations
		// The actual command/file events will be displayed by StreamingRenderer
		return nil
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
