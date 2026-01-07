// Package render provides consistent rendering utilities for agent output.
//
// This package centralizes agent output rendering to ensure a cohesive experience
// across all Deputy commands that use agents (explain --agent, fix --agent,
// triage --agent, etc.).
package render

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/ui"
)

// streamStats tracks statistics during AI streaming for the metadata footer.
type streamStats struct {
	Usage        ai.Usage // Token usage (if available)
	Model        string   // Model that was actually used (from DoneEvent)
	ToolCalls    int      // Number of tool calls made
	Commands     int      // Number of commands executed
	FileOps      int      // Number of file operations
	ThinkingMsgs int      // Number of thinking/reasoning messages (filtered from output)
}

// Config configures AI output rendering.
type Config struct {
	// Out is the primary output writer for AI responses.
	Out io.Writer
	// Err is the error output writer for spinners/progress.
	Err io.Writer
	// SpinnerMessage is the message shown during the spinner (e.g., "Generating analysis").
	SpinnerMessage string
	// RenderMarkdown enables glamour markdown rendering of the final output.
	RenderMarkdown bool
	// WordWrap sets the column width for text wrapping (default: 80).
	WordWrap int
	// ProviderName is the name of the AI provider (e.g., "codex", "claude").
	// Shown in the spinner and metadata footer.
	ProviderName string
	// Model is the model identifier being used (e.g., "gpt-4", "claude-sonnet").
	// Shown in metadata footer if provided.
	Model string
	// ShowMetadata enables showing duration and provider info after the response.
	ShowMetadata bool
}

// DefaultConfig returns a default render configuration.
func DefaultConfig() Config {
	return Config{
		Out:            os.Stdout,
		Err:            os.Stderr,
		SpinnerMessage: "Generating response",
		RenderMarkdown: true,
		WordWrap:       80,
	}
}

// StreamResponse streams an AI completion request and renders the output.
// It shows a spinner while waiting for the first token, then either:
// - Renders the collected response with glamour (if RenderMarkdown is true)
// - Prints the raw response (if RenderMarkdown is false)
//
// While waiting, the spinner updates with status hints based on agent events
// (e.g., "thinking", "reading files", "analyzing"). This gives users confidence
// that the agent is working.
//
// This provides a consistent user experience across all AI-enabled commands.
func StreamResponse(ctx context.Context, provider ai.Provider, req *ai.CompletionRequest, cfg Config) error {
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Err == nil {
		cfg.Err = os.Stderr
	}
	if cfg.WordWrap <= 0 {
		cfg.WordWrap = 80
	}

	// Use provider name from config, or fall back to provider.Name()
	providerName := cfg.ProviderName
	if providerName == "" {
		providerName = provider.Name()
	}

	// Build spinner message with provider info
	spinnerMsg := cfg.SpinnerMessage
	if spinnerMsg == "" {
		spinnerMsg = providerName
	}

	// Start spinner while waiting for AI response
	var progress *ui.Progress
	isTTY := ui.IsTTY(cfg.Out)
	if isTTY {
		progress = ui.NewProgress(cfg.Err, spinnerMsg)
		progress.SetSubMessage(ui.FormatStatusHint("starting"))
		progress.Start(ctx)
	}

	// Track timing and stats for metadata
	startTime := time.Now()
	var stats streamStats

	// Collect the full response (excluding internal status like [thinking])
	var response strings.Builder
	firstTextToken := true

	// Track if we were interrupted
	var interrupted bool

	// Stream the response
	for event, err := range provider.Stream(ctx, req) {
		// Check for context cancellation (CTRL+C)
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		if err != nil {
			if progress != nil {
				progress.Fail()
			}
			return fmt.Errorf("stream: %w", err)
		}
		switch e := event.(type) {
		case ai.TextEvent:
			text := e.Text
			// Check for [thinking] prefix - update spinner status but never include in output
			// This handles both "[thinking] ..." and "  [thinking] ..." (with leading whitespace)
			trimmed := strings.TrimSpace(text)
			if strings.HasPrefix(trimmed, "[thinking]") {
				stats.ThinkingMsgs++
				// Update spinner with a hint if still showing
				if progress != nil && firstTextToken {
					hint := extractStatusHint(strings.TrimPrefix(trimmed, "[thinking]"))
					if hint != "" {
						progress.SetSubMessage(ui.FormatStatusHint(hint))
					}
				}
				// Never include [thinking] in output, regardless of spinner state
				continue
			}
			// First real text clears the spinner
			if firstTextToken && progress != nil {
				progress.Clear()
				firstTextToken = false
			}
			response.WriteString(text)
		case ai.CommandEvent:
			stats.Commands++
			// Update spinner with command status
			if progress != nil && firstTextToken {
				hint := formatCommandHint(e.Command)
				progress.SetSubMessage(ui.FormatStatusHint(hint))
			}
		case ai.FileEvent:
			stats.FileOps++
			// Update spinner with file operation
			if progress != nil && firstTextToken {
				hint := e.Action
				if e.Path != "" {
					// Show just the filename
					parts := strings.Split(e.Path, "/")
					if len(parts) > 0 {
						hint = e.Action + " " + parts[len(parts)-1]
					}
				}
				progress.SetSubMessage(ui.FormatStatusHint(hint))
			}
		case ai.ToolCallEvent:
			stats.ToolCalls++
			// Update spinner with tool name
			if progress != nil && firstTextToken {
				progress.SetSubMessage(ui.FormatStatusHint(e.Call.Name))
			}
		case ai.StatusEvent:
			// Update spinner with status hint (e.g., "thinking", "working")
			if progress != nil && firstTextToken {
				progress.SetSubMessage(ui.FormatStatusHint(e.Status))
			}
		case ai.DoneEvent:
			// Capture final usage statistics and model
			stats.Usage = e.Usage
			if e.Model != "" {
				stats.Model = e.Model
			}
		case ai.ErrorEvent:
			if progress != nil {
				progress.Fail()
			}
			return fmt.Errorf("AI error: %w", e.Error())
		}
	}

	// Calculate duration
	duration := time.Since(startTime)

	// Clear spinner if no text was received or we were interrupted
	if progress != nil && (firstTextToken || interrupted) {
		progress.Clear()
	}

	// Handle interruption (CTRL+C)
	if interrupted {
		// Show any partial response we have
		if response.Len() > 0 {
			fmt.Fprintln(cfg.Out)
			fmt.Fprintln(cfg.Out, ui.StyleDim.Render("--- interrupted ---"))
			if cfg.RenderMarkdown {
				rendered, err := RenderMarkdown(response.String(), cfg.WordWrap)
				if err != nil {
					fmt.Fprintln(cfg.Out, response.String())
				} else {
					fmt.Fprint(cfg.Out, rendered)
				}
			} else {
				fmt.Fprintln(cfg.Out, response.String())
			}
		}
		// Show abbreviated metadata
		if cfg.ShowMetadata {
			meta := buildStyledMetadataLine(providerName, cfg.Model, req.Sandbox, duration, stats)
			fmt.Fprintln(cfg.Out, meta+ui.StyleDim.Render(" (interrupted)"))
		}
		return nil // Don't return error on graceful interrupt
	}

	// Render the response
	if response.Len() > 0 {
		if cfg.RenderMarkdown {
			rendered, err := RenderMarkdown(response.String(), cfg.WordWrap)
			if err != nil {
				// Fallback to plain text if glamour fails
				fmt.Fprintln(cfg.Out)
				fmt.Fprintln(cfg.Out, response.String())
			} else {
				fmt.Fprint(cfg.Out, rendered)
			}
		} else {
			fmt.Fprintln(cfg.Out, response.String())
		}
	}

	// Show metadata footer if enabled
	if cfg.ShowMetadata {
		meta := buildStyledMetadataLine(providerName, cfg.Model, req.Sandbox, duration, stats)
		fmt.Fprintln(cfg.Out, meta)
	}

	return nil
}

// buildStyledMetadataLine constructs a styled metadata line for the footer.
// Each element gets its own color for subtle visual distinction.
// Includes an AI star prefix (✦) to indicate AI-generated content.
func buildStyledMetadataLine(provider, model string, sandbox ai.Sandbox, duration time.Duration, stats streamStats) string {
	dot := ui.StyleAgentDot.Render(" · ")
	var parts []string

	// Use model from stats (reported by provider) if available, otherwise fall back to config
	effectiveModel := stats.Model
	if effectiveModel == "" {
		effectiveModel = model
	}

	// Provider/model info - always show both if model is available
	if effectiveModel != "" {
		parts = append(parts, ui.StyleAgentProvider.Render(provider)+
			ui.StyleAgentDot.Render("/")+
			ui.StyleAgentModel.Render(effectiveModel))
	} else {
		parts = append(parts, ui.StyleAgentProvider.Render(provider))
	}

	// Sandbox mode (only if not default)
	if sandbox != "" && sandbox != ai.SandboxWorkspaceWrite {
		parts = append(parts, ui.StyleAgentSandbox.Render(string(sandbox)))
	}

	// Token usage (if available)
	if stats.Usage.TotalTokens > 0 {
		parts = append(parts, formatStyledTokens(stats.Usage))
	}

	// Duration (format nicely)
	parts = append(parts, ui.StyleAgentDuration.Render(formatDuration(duration)))

	// Prefix with AI star indicator
	return ui.AIStarPrefix() + strings.Join(parts, dot)
}

// buildMetadataLine constructs a plain metadata line (for testing/non-TTY).
func buildMetadataLine(provider, model string, sandbox ai.Sandbox, duration time.Duration, stats streamStats) string {
	var parts []string

	// Use model from stats (reported by provider) if available, otherwise fall back to config
	effectiveModel := stats.Model
	if effectiveModel == "" {
		effectiveModel = model
	}

	// Provider/model info
	if effectiveModel != "" {
		parts = append(parts, fmt.Sprintf("%s/%s", provider, effectiveModel))
	} else {
		parts = append(parts, provider)
	}

	// Sandbox mode (only if not default)
	if sandbox != "" && sandbox != ai.SandboxWorkspaceWrite {
		parts = append(parts, string(sandbox))
	}

	// Token usage (if available)
	if stats.Usage.TotalTokens > 0 {
		parts = append(parts, formatTokens(stats.Usage))
	}

	// Duration (format nicely)
	parts = append(parts, formatDuration(duration))

	// Prefix with AI star indicator
	return "✦ " + strings.Join(parts, " · ")
}

// formatStyledTokens formats token usage with styled output.
func formatStyledTokens(usage ai.Usage) string {
	if usage.TotalTokens == 0 {
		return ""
	}
	// Show total tokens, with in/out breakdown if both available
	if usage.PromptTokens > 0 && usage.CompletionTokens > 0 {
		return ui.StyleAgentTokens.Render(formatNumber(usage.TotalTokens)) +
			ui.StyleAgentTokensLabel.Render(" tokens (") +
			ui.StyleAgentTokens.Render(formatNumber(usage.PromptTokens)) +
			ui.StyleAgentTokensLabel.Render(" in, ") +
			ui.StyleAgentTokens.Render(formatNumber(usage.CompletionTokens)) +
			ui.StyleAgentTokensLabel.Render(" out)")
	}
	return ui.StyleAgentTokens.Render(formatNumber(usage.TotalTokens)) +
		ui.StyleAgentTokensLabel.Render(" tokens")
}

// formatTokens formats token usage for display (plain text).
func formatTokens(usage ai.Usage) string {
	if usage.TotalTokens == 0 {
		return ""
	}
	// Show total tokens, with in/out breakdown if both available
	if usage.PromptTokens > 0 && usage.CompletionTokens > 0 {
		return fmt.Sprintf("%s tokens (%s in, %s out)",
			formatNumber(usage.TotalTokens),
			formatNumber(usage.PromptTokens),
			formatNumber(usage.CompletionTokens))
	}
	return fmt.Sprintf("%s tokens", formatNumber(usage.TotalTokens))
}

// formatNumber formats a number with K/M suffixes for readability.
func formatNumber(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 10_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.2fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// formatDuration formats a duration for display (e.g., "1.2s", "45s", "2m 30s").
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	if secs == 0 {
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%dm %ds", mins, secs)
}

// cleanCommandString removes shell quoting artifacts from command strings.
// Handles patterns like "['cmd arg']", "['cmd', 'arg']", etc.
func cleanCommandString(cmd string) string {
	// Remove leading/trailing brackets and quotes
	cmd = strings.TrimSpace(cmd)

	// Handle array-style commands: ['cmd arg'] or ['cmd', 'arg']
	if strings.HasPrefix(cmd, "[") && strings.HasSuffix(cmd, "]") {
		cmd = cmd[1 : len(cmd)-1]
	}

	// Handle comma-separated array elements with single quotes: 'cmd', 'arg' -> cmd arg
	if strings.Contains(cmd, "', '") {
		parts := strings.Split(cmd, "', '")
		for i, p := range parts {
			parts[i] = strings.Trim(p, "'\"")
		}
		cmd = strings.Join(parts, " ")
	} else if strings.Contains(cmd, "\", \"") {
		// Handle comma-separated array elements with double quotes: "cmd", "arg" -> cmd arg
		parts := strings.Split(cmd, "\", \"")
		for i, p := range parts {
			parts[i] = strings.Trim(p, "'\"")
		}
		cmd = strings.Join(parts, " ")
	} else {
		// Remove surrounding quotes (single or double) for simple cases
		cmd = strings.Trim(cmd, "'\"")
	}

	return strings.TrimSpace(cmd)
}

// formatCommandHint creates a concise command hint for the spinner.
// Shows the command with key arguments, truncated to fit spinner display.
func formatCommandHint(cmd string) string {
	if cmd == "" {
		return "running"
	}

	// Clean up shell quoting artifacts that may appear in command strings
	// e.g., "['rg pattern']" -> "rg pattern"
	cmd = cleanCommandString(cmd)

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "running"
	}

	// Get the base command name (strip path)
	base := parts[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}

	// For common commands, show more context
	switch base {
	case "rg", "grep":
		// Show search pattern if available
		if len(parts) > 1 {
			pattern := parts[1]
			if len(pattern) > 15 {
				pattern = pattern[:12] + "..."
			}
			return base + " " + pattern
		}
	case "sed", "awk":
		// Just show the command name - patterns are often complex
		return base
	case "cat", "head", "tail", "less":
		// Show filename if available
		if len(parts) > 1 {
			file := parts[len(parts)-1]
			if idx := strings.LastIndex(file, "/"); idx >= 0 {
				file = file[idx+1:]
			}
			if len(file) > 20 {
				file = file[:17] + "..."
			}
			return base + " " + file
		}
	case "go":
		// Show go subcommand
		if len(parts) > 1 {
			return "go " + parts[1]
		}
	case "git":
		// Show git subcommand
		if len(parts) > 1 {
			return "git " + parts[1]
		}
	case "npm", "yarn", "pnpm":
		// Show package manager subcommand
		if len(parts) > 1 {
			return base + " " + parts[1]
		}
	case "docker", "kubectl":
		// Show subcommand
		if len(parts) > 1 {
			return base + " " + parts[1]
		}
	case "sh", "bash", "zsh":
		// For shell commands, try to show the actual command
		for i, p := range parts {
			if p == "-c" && i+1 < len(parts) {
				// Get the actual command being run
				shellCmd := parts[i+1]
				shellParts := strings.Fields(shellCmd)
				if len(shellParts) > 0 {
					return formatCommandHint(shellCmd)
				}
			}
		}
		return base
	}

	// Default: show command with first meaningful arg
	if len(parts) > 1 {
		arg := parts[1]
		// Skip common flags
		if strings.HasPrefix(arg, "-") && len(parts) > 2 {
			arg = parts[2]
		}
		if !strings.HasPrefix(arg, "-") {
			if len(arg) > 15 {
				arg = arg[:12] + "..."
			}
			return base + " " + arg
		}
	}

	return base
}

// extractStatusHint extracts a short status hint from thinking/reasoning text.
// Returns a brief phrase suitable for spinner display (max ~20 chars).
func extractStatusHint(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "thinking"
	}

	// Common patterns to extract hints from
	patterns := []struct {
		prefix string
		hint   string
	}{
		{"analyzing", "analyzing"},
		{"reading", "reading"},
		{"examining", "examining"},
		{"looking at", "examining"},
		{"checking", "checking"},
		{"reviewing", "reviewing"},
		{"considering", "considering"},
		{"evaluating", "evaluating"},
		{"searching", "searching"},
		{"finding", "searching"},
		{"let me", "thinking"},
		{"i'll", "thinking"},
		{"i need to", "thinking"},
		{"first", "thinking"},
		{"now", "thinking"},
	}

	lower := strings.ToLower(text)
	for _, p := range patterns {
		if strings.HasPrefix(lower, p.prefix) {
			return p.hint
		}
	}

	// Default: just "thinking"
	return "thinking"
}

// RenderMarkdown renders markdown text using glamour with appropriate styling.
func RenderMarkdown(content string, wordWrap int) (string, error) {
	if wordWrap <= 0 {
		wordWrap = 80
	}
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(wordWrap),
	)
	if err != nil {
		return "", err
	}
	return renderer.Render(content)
}

// StreamingRenderer provides real-time rendering of AI events.
// This is used for agentic commands (fix --agent, triage --agent) where
// users want to see what the agent is doing in real-time.
type StreamingRenderer struct {
	out          io.Writer
	err          io.Writer
	providerName string
	progress     *ui.Progress
	firstEvent   bool
}

// NewStreamingRenderer creates a renderer for real-time AI event streaming.
func NewStreamingRenderer(out, errW io.Writer, providerName string) *StreamingRenderer {
	if out == nil {
		out = os.Stdout
	}
	if errW == nil {
		errW = os.Stderr
	}
	return &StreamingRenderer{
		out:          out,
		err:          errW,
		providerName: providerName,
		firstEvent:   true,
	}
}

// StartSpinner begins a spinner with the given message.
// Call this before starting the AI stream.
func (r *StreamingRenderer) StartSpinner(ctx context.Context, message string) {
	if ui.IsTTY(r.out) {
		r.progress = ui.NewProgress(r.err, message)
		r.progress.Start(ctx)
	}
}

// RenderEvent renders a single AI stream event.
// It automatically clears the spinner on the first event.
func (r *StreamingRenderer) RenderEvent(event ai.StreamEvent) {
	if event == nil {
		return
	}

	// Clear spinner on first event
	if r.firstEvent && r.progress != nil {
		r.progress.Clear()
		r.firstEvent = false
	}

	switch e := event.(type) {
	case ai.TextEvent:
		text := strings.TrimSpace(e.Text)
		if text != "" {
			fmt.Fprintf(r.out, "%s %s\n", ui.StyleManager.Render(r.providerName), text)
		}
	case ai.CommandEvent:
		status := e.Status
		if e.ExitCode != nil {
			status = fmt.Sprintf("%s (exit %d)", status, *e.ExitCode)
		}
		fmt.Fprintf(r.out, "%s %s %s\n", ui.StyleManager.Render("$"), ui.StylePackageName.Render(e.Command), ui.StyleDim.Render(status))
		if strings.TrimSpace(e.Output) != "" {
			fmt.Fprintf(r.out, "%s\n", strings.TrimSpace(e.Output))
		}
	case ai.FileEvent:
		fmt.Fprintf(r.out, "%s %s %s\n", ui.StylePath.Render(fmt.Sprintf("[%s]", e.Action)), e.Path, ui.StyleDim.Render(e.Status))
	case ai.ErrorEvent:
		fmt.Fprintf(r.out, "%s %s\n", ui.StyleRemoved.Render("error:"), e.Message)
	case ai.ToolCallEvent:
		fmt.Fprintf(r.out, "%s %s\n", ui.StyleDim.Render("tool:"), e.Call.Name)
	case ai.DoneEvent:
		// Session complete, handled by caller
	}
}

// Fail marks the spinner as failed and clears it.
func (r *StreamingRenderer) Fail() {
	if r.progress != nil {
		r.progress.Fail()
		r.progress = nil
	}
}

// Clear clears the spinner without marking success/failure.
func (r *StreamingRenderer) Clear() {
	if r.progress != nil {
		r.progress.Clear()
		r.progress = nil
	}
}
