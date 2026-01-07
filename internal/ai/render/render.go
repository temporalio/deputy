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
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/ui"
)

// streamStats tracks statistics during AI streaming for the metadata footer.
type streamStats struct {
	Usage          ai.Usage // Token usage (if available)
	Model          string   // Model that was actually used (from DoneEvent)
	ToolCalls      int      // Number of tool calls made
	Commands       int      // Number of commands executed
	FailedCommands int      // Number of commands that failed (exit != 0)
	FileOps        int      // Number of file operations
	ThinkingMsgs   int      // Number of thinking/reasoning messages (filtered from output)
}

// AgentStatus represents the overall outcome of an agent session.
type AgentStatus int

const (
	// AgentStatusSuccess indicates all commands succeeded.
	AgentStatusSuccess AgentStatus = iota
	// AgentStatusPartial indicates some commands failed but work was done.
	AgentStatusPartial
	// AgentStatusFailed indicates the agent encountered critical failures.
	AgentStatusFailed
	// AgentStatusInterrupted indicates the user interrupted the session.
	AgentStatusInterrupted
)

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
// Uses a dark style optimized for CLI output with subtle styling.
func RenderMarkdown(content string, wordWrap int) (string, error) {
	if wordWrap <= 0 {
		wordWrap = 80
	}

	// Use DarkStyle for consistent appearance, but modify for subtle CLI output
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(wordWrap),
		glamour.WithEmoji(), // Support emoji rendering
	)
	if err != nil {
		return "", err
	}
	return renderer.Render(content)
}

// StreamingRenderer provides real-time rendering of AI events.
// This is used for agentic commands (fix --agent) where users want to see
// what the agent is doing in real-time with command/file events.
//
// Unlike StreamResponse (which collects all output for glamour rendering),
// StreamingRenderer shows events as they occur - useful when the agent is
// making changes and you want immediate visibility.
//
// Output format (non-verbose):
//
//	✓ go mod tidy                    (success)
//	✗ go test ./...                  (failure with exit code)
//	│ [first 3 lines of output...]
//
// The final agent text/summary is collected and rendered with glamour markdown.
type StreamingRenderer struct {
	out            io.Writer
	err            io.Writer
	providerName   string
	model          string
	sandbox        ai.Sandbox
	progress       *ui.Progress
	ctx            context.Context // for restarting spinner
	spinnerActive  bool            // whether spinner is currently showing
	startTime      time.Time
	stats          streamStats
	verbose        bool            // show full command output
	maxOutputLines int             // max lines in compact mode (default: 3)
	summaryText    strings.Builder // collected text for final glamour rendering
	isTTY          bool
	cmdStartTimes  map[string]time.Time // track when commands started (for duration)
}

// StreamingConfig configures the streaming renderer.
type StreamingConfig struct {
	// Out is the primary output writer for AI responses.
	Out io.Writer
	// Err is the error output writer for spinners/progress.
	Err io.Writer
	// ProviderName is the name of the AI provider (e.g., "codex", "claude").
	ProviderName string
	// Model is the model identifier being used.
	Model string
	// Sandbox is the sandbox mode for the agent.
	Sandbox ai.Sandbox
	// ShowMetadata enables the footer with duration/token info.
	ShowMetadata bool
	// Verbose shows full command output instead of compact summaries.
	Verbose bool
	// MaxOutputLines limits command output lines in non-verbose mode (default: 3).
	MaxOutputLines int
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
		out:            out,
		err:            errW,
		providerName:   providerName,
		startTime:      time.Now(),
		maxOutputLines: 3, // default
		isTTY:          ui.IsTTY(out),
		cmdStartTimes:  make(map[string]time.Time),
	}
}

// NewStreamingRendererWithConfig creates a renderer with full configuration.
func NewStreamingRendererWithConfig(cfg StreamingConfig) *StreamingRenderer {
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	errW := cfg.Err
	if errW == nil {
		errW = os.Stderr
	}
	maxLines := cfg.MaxOutputLines
	if maxLines <= 0 {
		maxLines = 3 // default
	}
	return &StreamingRenderer{
		out:            out,
		err:            errW,
		providerName:   cfg.ProviderName,
		model:          cfg.Model,
		sandbox:        cfg.Sandbox,
		startTime:      time.Now(),
		verbose:        cfg.Verbose,
		maxOutputLines: maxLines,
		isTTY:          ui.IsTTY(out),
		cmdStartTimes:  make(map[string]time.Time),
	}
}

// StartSpinner begins a spinner with the given message.
// Call this before starting the AI stream.
func (r *StreamingRenderer) StartSpinner(ctx context.Context, message string) {
	r.ctx = ctx
	if r.isTTY {
		r.progress = ui.NewProgress(r.err, message)
		r.progress.SetSubMessage(ui.FormatStatusHint("starting"))
		r.progress.Start(ctx)
		r.spinnerActive = true
	}
	r.startTime = time.Now()
}

// restartSpinner restarts the spinner after output with a new status hint.
// This keeps the user informed that work is still happening between events.
func (r *StreamingRenderer) restartSpinner(hint string) {
	if !r.isTTY || r.ctx == nil {
		return
	}
	// Create a fresh spinner
	r.progress = ui.NewProgress(r.err, r.providerName)
	r.progress.SetSubMessage(ui.FormatStatusHint(hint))
	r.progress.Start(r.ctx)
	r.spinnerActive = true
}

// clearSpinner clears the spinner before outputting content.
func (r *StreamingRenderer) clearSpinner() {
	if r.progress != nil && r.spinnerActive {
		r.progress.Clear()
		r.spinnerActive = false
	}
}

// showContinuation was used to print a visual connector between command output
// and the next spinner. Now we rely on vertical spacing from the threaded output
// lines themselves, so this is a no-op.
func (r *StreamingRenderer) showContinuation() {
	// No-op: removed the ⇣ arrow per user feedback - the threaded │ lines provide
	// sufficient visual continuity without additional connectors.
}

// redactSecrets scans text for potential secrets and redacts them.
// Returns the redacted text and whether any redactions were made.
func redactSecrets(text string) (string, bool) {
	redacted := false
	result := text

	// Patterns that likely indicate secrets (case-insensitive matching)
	secretPatterns := []struct {
		pattern string
		name    string
	}{
		// API keys and tokens (common formats)
		{`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`, "API_KEY"},
		{`(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`, "SECRET_KEY"},
		{`(?i)(access[_-]?token|accesstoken)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`, "ACCESS_TOKEN"},
		{`(?i)(auth[_-]?token|authtoken)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`, "AUTH_TOKEN"},
		{`(?i)(bearer)\s+([a-zA-Z0-9_\-\.]{20,})`, "BEARER_TOKEN"},

		// Passwords
		{`(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`, "PASSWORD"},

		// AWS
		{`(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*['"]?(AKIA[A-Z0-9]{16})['"]?`, "AWS_KEY"},
		{`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`, "AWS_SECRET"},

		// GitHub tokens
		{`(ghp_[a-zA-Z0-9]{36,})`, "GITHUB_TOKEN"},
		{`(gho_[a-zA-Z0-9]{36,})`, "GITHUB_TOKEN"},
		{`(ghu_[a-zA-Z0-9]{36,})`, "GITHUB_TOKEN"},
		{`(ghs_[a-zA-Z0-9]{36,})`, "GITHUB_TOKEN"},
		{`(ghr_[a-zA-Z0-9]{36,})`, "GITHUB_TOKEN"},

		// Private keys
		{`-----BEGIN[A-Z ]*PRIVATE KEY-----`, "PRIVATE_KEY"},

		// Generic long hex strings that look like secrets
		{`(?i)(token|key|secret|credential)\s*[=:]\s*['"]?([a-f0-9]{32,})['"]?`, "SECRET"},
	}

	for _, sp := range secretPatterns {
		re, err := regexp.Compile(sp.pattern)
		if err != nil {
			continue
		}
		if re.MatchString(result) {
			result = re.ReplaceAllString(result, fmt.Sprintf("[REDACTED:%s]", sp.name))
			redacted = true
		}
	}

	return result, redacted
}

// RenderEvent renders a single AI stream event.
// It manages a spinner that shows activity between events, clearing it before
// output and restarting it after to keep users informed of ongoing work.
//
// Commands are rendered in a compact format:
//
//	✓ go mod tidy
//	✗ go test ./...  (exit 1)
//	  │ FAIL: TestFoo
//
// Text from the agent is collected and rendered with glamour in Finish().
func (r *StreamingRenderer) RenderEvent(event ai.StreamEvent) {
	if event == nil {
		return
	}

	switch e := event.(type) {
	case ai.TextEvent:
		text := e.Text
		trimmed := strings.TrimSpace(text)

		// Handle [thinking] - update spinner status but don't output
		if strings.HasPrefix(trimmed, "[thinking]") {
			r.stats.ThinkingMsgs++
			if r.progress != nil {
				hint := extractStatusHint(strings.TrimPrefix(trimmed, "[thinking]"))
				if hint != "" {
					r.progress.SetSubMessage(ui.FormatStatusHint(hint))
				}
			}
			return
		}

		// Skip empty text
		if trimmed == "" {
			return
		}

		// Collect text for final glamour rendering instead of printing immediately
		r.summaryText.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			r.summaryText.WriteString("\n")
		}

	case ai.CommandEvent:
		r.stats.Commands++

		// Track failed commands for overall status
		if e.ExitCode != nil && *e.ExitCode != 0 {
			r.stats.FailedCommands++
		}

		// Normalize status for comparison
		status := strings.ToLower(strings.TrimSpace(e.Status))

		// For in-progress commands, track start time and update spinner
		if status == "in_progress" || status == "running" || status == "pending" {
			// Record when this command started
			r.cmdStartTimes[e.Command] = time.Now()

			hint := formatCommandHint(e.Command)
			if r.progress != nil {
				r.progress.SetSubMessage(ui.FormatStatusHint(hint))
			} else {
				// Spinner was cleared, restart it
				r.restartSpinner(hint)
			}
			return
		}

		// Calculate command duration if we tracked its start
		var cmdDuration time.Duration
		if startTime, ok := r.cmdStartTimes[e.Command]; ok {
			cmdDuration = time.Since(startTime)
			delete(r.cmdStartTimes, e.Command)
		}

		// Clear spinner before showing completed/failed command
		r.clearSpinner()

		// Render the command in compact format with success/fail indicator
		r.renderCommand(e, cmdDuration)

		// Show continuation indicator and restart spinner
		r.showContinuation()
		r.restartSpinner("working")

	case ai.FileEvent:
		r.stats.FileOps++

		// Normalize status for comparison
		status := strings.ToLower(strings.TrimSpace(e.Status))

		// For in-progress file ops, update spinner
		if status == "in_progress" || status == "running" || status == "pending" {
			hint := e.Action
			if e.Path != "" {
				parts := strings.Split(e.Path, "/")
				if len(parts) > 0 {
					hint = e.Action + " " + parts[len(parts)-1]
				}
			}
			if r.progress != nil {
				r.progress.SetSubMessage(ui.FormatStatusHint(hint))
			} else {
				r.restartSpinner(hint)
			}
			return
		}

		// Clear spinner before showing completed file operation
		r.clearSpinner()

		// Render file operation in compact format
		r.renderFileOp(e)

		// Show continuation indicator and restart spinner
		r.showContinuation()
		r.restartSpinner("working")

	case ai.ToolCallEvent:
		r.stats.ToolCalls++

		// Update or restart spinner with tool name
		if r.progress != nil {
			r.progress.SetSubMessage(ui.FormatStatusHint(e.Call.Name))
		} else {
			r.restartSpinner(e.Call.Name)
		}

	case ai.StatusEvent:
		// Update or restart spinner with status hint
		if r.progress != nil {
			r.progress.SetSubMessage(ui.FormatStatusHint(e.Status))
		} else {
			r.restartSpinner(e.Status)
		}

	case ai.ErrorEvent:
		// Clear spinner and show error
		r.clearSpinner()
		fmt.Fprintf(r.out, "%s %s\n", ui.StyleRemoved.Render("✗ error:"), e.Message)

	case ai.DoneEvent:
		// Capture final usage statistics and model
		r.stats.Usage = e.Usage
		if e.Model != "" {
			r.stats.Model = e.Model
		}
	}
}

// renderCommand renders a command event in compact format with colored status indicators.
//
// Format (success):
//
//	• go mod tidy                              [1.2s]
//	│ upgraded golang.org/x/crypto v0.44.0 => v0.45.0
//
// Format (failure):
//
//	• go test ./...                            [exit 1 · 3.4s · 150 lines]
//	│ FAIL: TestFoo
//	│ ... 140 more lines ...
//	│ FAIL
func (r *StreamingRenderer) renderCommand(e ai.CommandEvent, duration time.Duration) {
	// Clean up the command string
	cmd := cleanCommandString(e.Command)

	// Determine success/failure
	failed := e.ExitCode != nil && *e.ExitCode != 0

	// Choose indicator and line styles based on status
	var indicator, lineStyle lipgloss.Style
	if failed {
		indicator = ui.StyleStatusError
		lineStyle = ui.StyleLineError
	} else {
		indicator = ui.StyleStatusSuccess
		lineStyle = ui.StyleLineSuccess
	}

	// Redact secrets from output
	output := strings.TrimSpace(e.Output)
	output, secretsRedacted := redactSecrets(output)

	// Count output lines for metadata
	outputLines := 0
	if output != "" {
		outputLines = len(strings.Split(output, "\n"))
	}

	// Build metadata tags with intentional coloring
	var styledTags []string
	dot := ui.StyleDim.Render(" · ")

	// Exit code (for failures) - error red
	if failed && e.ExitCode != nil {
		styledTags = append(styledTags, ui.StyleStatusError.Render(fmt.Sprintf("exit %d", *e.ExitCode)))
	}

	// Duration (if we tracked it) - dim
	if duration > 0 {
		styledTags = append(styledTags, ui.StyleDim.Render(formatDuration(duration)))
	}

	// Output line count (if significant and truncated) - dim
	if outputLines > r.maxOutputLines*2+1 {
		styledTags = append(styledTags, ui.StyleDim.Render(fmt.Sprintf("%d lines", outputLines)))
	}

	// Secrets redacted warning - amber warning
	if secretsRedacted {
		styledTags = append(styledTags, ui.StyleStatusWarning.Render("redacted"))
	}

	// Format the metadata suffix with styled brackets
	metaSuffix := ""
	if len(styledTags) > 0 {
		metaSuffix = "  " + ui.StyleDim.Render("[") + strings.Join(styledTags, dot) + ui.StyleDim.Render("]")
	}

	// Format the command line with colored bullet indicator and metadata
	fmt.Fprintf(r.out, "%s %s%s\n",
		indicator.Render("•"),
		ui.StylePackageName.Render(cmd),
		metaSuffix)

	// Show output with colored threading
	if output != "" {
		r.renderOutputLines(output, failed, lineStyle)
	}
}

// renderFileOp renders a file operation in compact format with colored indicator.
//
// Format:
//
//	• [write] go.mod
//	• [read] internal/foo/bar.go
func (r *StreamingRenderer) renderFileOp(e ai.FileEvent) {
	// Shorten path for display (show last 2 components)
	path := e.Path
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		path = ".../" + strings.Join(parts[len(parts)-2:], "/")
	}

	// File ops are generally successful if we get here
	fmt.Fprintf(r.out, "%s %s %s\n",
		ui.StyleStatusSuccess.Render("•"),
		ui.StyleDim.Render(fmt.Sprintf("[%s]", e.Action)),
		ui.StylePath.Render(path))
}

// renderOutputLines renders command output with a colored vertical line.
// Shows head (first 3) and tail (last 3) of long outputs with ellipsis.
//
// Format:
//
//	│ first line of output
//	│ second line
//	│ third line
//	│ ...
//	│ third to last
//	│ second to last
//	│ last line
func (r *StreamingRenderer) renderOutputLines(output string, isError bool, lineStyle lipgloss.Style) {
	lines := strings.Split(output, "\n")

	// Filter empty lines
	var nonEmpty []string
	for _, line := range lines {
		if line != "" {
			nonEmpty = append(nonEmpty, line)
		}
	}
	if len(nonEmpty) == 0 {
		return
	}

	// In verbose mode, show everything
	if r.verbose {
		for _, line := range nonEmpty {
			fmt.Fprintf(r.out, "%s %s\n", lineStyle.Render("│"), line)
		}
		return
	}

	// Non-verbose: show first N and last N lines with ellipsis in between
	headLines := r.maxOutputLines // default: 3
	tailLines := r.maxOutputLines // default: 3

	// Find important lines (errors, failures, etc.)
	importantIdxs := make(map[int]bool)
	for i, line := range nonEmpty {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") ||
			strings.Contains(lower, "fail") ||
			strings.Contains(lower, "panic") ||
			strings.HasPrefix(line, "--- FAIL") ||
			strings.HasPrefix(line, "FAIL") {
			importantIdxs[i] = true
		}
	}

	// Calculate what to show
	totalLines := len(nonEmpty)
	if totalLines <= headLines+tailLines+1 {
		// Few enough lines to show all
		for i, line := range nonEmpty {
			textStyle := ui.StyleDim
			if importantIdxs[i] && isError {
				textStyle = ui.StyleStatusError
			}
			fmt.Fprintf(r.out, "%s %s\n", lineStyle.Render("│"), textStyle.Render(line))
		}
		return
	}

	// Show head (first N lines)
	for i := 0; i < headLines; i++ {
		line := nonEmpty[i]
		textStyle := ui.StyleDim
		if importantIdxs[i] && isError {
			textStyle = ui.StyleStatusError
		}
		fmt.Fprintf(r.out, "%s %s\n", lineStyle.Render("│"), textStyle.Render(line))
	}

	// Show ellipsis
	skipped := totalLines - headLines - tailLines
	fmt.Fprintf(r.out, "%s %s\n",
		lineStyle.Render("│"),
		ui.StyleDim.Render(fmt.Sprintf("... %d more lines ...", skipped)))

	// Show tail (last N lines)
	for i := totalLines - tailLines; i < totalLines; i++ {
		line := nonEmpty[i]
		textStyle := ui.StyleDim
		if importantIdxs[i] && isError {
			textStyle = ui.StyleStatusError
		}
		fmt.Fprintf(r.out, "%s %s\n", lineStyle.Render("│"), textStyle.Render(line))
	}
}

// Finish completes the streaming session and optionally shows metadata footer.
// Call this after all events have been processed.
//
// If the agent produced any text summary, it will be rendered with glamour markdown
// for a polished final output.
//
// The session ends with a status endcap showing the overall outcome:
//
//	■ done                    (all commands succeeded)
//	■ done (2 failed)         (some commands failed)
//	■ interrupted             (user cancelled)
func (r *StreamingRenderer) Finish(showMetadata bool) {
	// Clear any remaining spinner
	r.clearSpinner()

	// Check if we were interrupted
	interrupted := r.ctx != nil && r.ctx.Err() != nil

	// Determine overall status
	status := r.computeStatus(interrupted)

	// Show status endcap (visual terminator for the command stream)
	r.renderStatusEndcap(status)

	// Render collected summary text with glamour
	if summary := strings.TrimSpace(r.summaryText.String()); summary != "" {
		// Use glamour for nice markdown rendering in TTY
		if r.isTTY {
			rendered, err := RenderMarkdown(summary, 80)
			if err == nil {
				fmt.Fprint(r.out, rendered)
			} else {
				// Fallback to plain text
				fmt.Fprintln(r.out, summary)
			}
		} else {
			// Non-TTY: plain text
			fmt.Fprintln(r.out, summary)
		}
	}

	// Show metadata footer
	if showMetadata {
		duration := time.Since(r.startTime)
		model := r.stats.Model
		if model == "" {
			model = r.model
		}
		meta := buildStyledMetadataLine(r.providerName, model, r.sandbox, duration, r.stats)
		fmt.Fprintln(r.out)
		fmt.Fprintln(r.out, meta)
	}
}

// computeStatus determines the overall agent session status.
func (r *StreamingRenderer) computeStatus(interrupted bool) AgentStatus {
	if interrupted {
		return AgentStatusInterrupted
	}
	if r.stats.FailedCommands > 0 {
		if r.stats.FailedCommands == r.stats.Commands {
			return AgentStatusFailed
		}
		return AgentStatusPartial
	}
	return AgentStatusSuccess
}

// renderStatusEndcap renders a visual terminator showing the session outcome.
// Uses a small black square (▪) as an "endcap" for the command stream.
//
// Format:
//
//	▪ done                    (green - all succeeded)
//	▪ done (1 failed)         (amber - partial success)
//	▪ failed                  (red - all failed)
//	▪ interrupted             (dim - user cancelled)
func (r *StreamingRenderer) renderStatusEndcap(status AgentStatus) {
	var label string
	var style lipgloss.Style

	switch status {
	case AgentStatusSuccess:
		label = "done"
		style = ui.StyleStatusSuccess
	case AgentStatusPartial:
		label = fmt.Sprintf("done (%d failed)", r.stats.FailedCommands)
		style = ui.StyleStatusWarning
	case AgentStatusFailed:
		label = "failed"
		style = ui.StyleStatusError
	case AgentStatusInterrupted:
		label = "interrupted"
		style = ui.StyleDim
	}

	fmt.Fprintf(r.out, "%s %s\n", style.Render("▪"), ui.StyleDim.Render(label))
}

// Status returns the overall status of the agent session.
// Call this after Finish() to get the status for exit codes.
func (r *StreamingRenderer) Status() AgentStatus {
	interrupted := r.ctx != nil && r.ctx.Err() != nil
	return r.computeStatus(interrupted)
}

// ExitCode returns an appropriate exit code for the agent session.
// 0 = success, 1 = partial/failed, 130 = interrupted (SIGINT convention)
func (r *StreamingRenderer) ExitCode() int {
	switch r.Status() {
	case AgentStatusSuccess:
		return 0
	case AgentStatusInterrupted:
		return 130 // Convention for SIGINT
	default:
		return 1
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

// Stats returns the collected statistics from the streaming session.
func (r *StreamingRenderer) Stats() streamStats {
	return r.stats
}

// Duration returns the time elapsed since the renderer started.
func (r *StreamingRenderer) Duration() time.Duration {
	return time.Since(r.startTime)
}
