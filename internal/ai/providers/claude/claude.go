// Package claude provides an AI provider implementation using Anthropic's Claude CLI.
//
// Claude Code is a full agentic provider that can execute commands, modify files,
// and perform complex multi-step operations autonomously via the `claude` CLI.
package claude

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"os/exec"
	"strings"
	"sync"

	"github.com/temporalio/deputy/internal/ai"
)

func init() {
	ai.MustRegisterProvider(&Provider{})
}

// Provider implements ai.Provider using the Claude CLI.
type Provider struct{}

var _ ai.Provider = (*Provider)(nil)

// Name returns the provider identifier.
func (p *Provider) Name() string { return "claude" }

// Capabilities describes what the Claude provider can do.
func (p *Provider) Capabilities() ai.ProviderCapabilities {
	return ai.ProviderCapabilities{
		Streaming:         true,
		ToolUse:           true,
		Vision:            true,
		Agentic:           true,
		SessionResumption: true,
		MaxContextTokens:  200000, // Claude 3.5 Sonnet
	}
}

// Complete sends a prompt and waits for the full response.
func (p *Provider) Complete(ctx context.Context, req *ai.CompletionRequest) (*ai.CompletionResponse, error) {
	var output strings.Builder
	var sessionID string
	var lastErr error

	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			lastErr = err
			continue
		}
		switch e := event.(type) {
		case ai.TextEvent:
			output.WriteString(e.Text)
		case ai.ErrorEvent:
			lastErr = e.Error()
		case ai.DoneEvent:
			sessionID = e.SessionID
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return &ai.CompletionResponse{
		Text:         output.String(),
		SessionID:    sessionID,
		FinishReason: ai.FinishReasonStop,
	}, nil
}

// Stream sends a prompt and yields events as they occur.
func (p *Provider) Stream(ctx context.Context, req *ai.CompletionRequest) iter.Seq2[ai.StreamEvent, error] {
	return func(yield func(ai.StreamEvent, error) bool) {
		args := buildArgs(req)

		cmd := exec.CommandContext(ctx, "claude", args...)
		if req.WorkDir != "" {
			cmd.Dir = req.WorkDir
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			yield(nil, fmt.Errorf("create stdout pipe: %w", err))
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			yield(nil, fmt.Errorf("create stderr pipe: %w", err))
			return
		}

		if err := cmd.Start(); err != nil {
			yield(nil, fmt.Errorf("start claude: %w", err))
			return
		}

		// Use a channel to collect events from goroutines
		// This avoids race conditions with concurrent yield calls
		events := make(chan eventOrError, 100)
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			streamOutput(stdout, events)
		}()
		go func() {
			defer wg.Done()
			streamErrors(stderr, events)
		}()

		// Close events channel when both goroutines complete
		go func() {
			wg.Wait()
			close(events)
		}()

		// Yield events from the channel (single-threaded)
		for ev := range events {
			if ev.err != nil {
				if !yield(nil, ev.err) {
					cmd.Process.Kill()
					return
				}
				continue
			}
			if ev.event != nil {
				if !yield(ev.event, nil) {
					cmd.Process.Kill()
					return
				}
			}
		}

		// Wait for command to complete
		cmdErr := cmd.Wait()
		success := cmd.ProcessState != nil && cmd.ProcessState.Success()

		if cmdErr != nil && !success {
			yield(ai.ErrorEvent{Message: cmdErr.Error(), Err: cmdErr}, nil)
		}

		yield(ai.DoneEvent{FinishReason: ai.FinishReasonStop}, nil)
	}
}

// eventOrError is used to pass events through a channel.
type eventOrError struct {
	event ai.StreamEvent
	err   error
}

// buildArgs constructs the command line arguments for the Claude CLI.
func buildArgs(req *ai.CompletionRequest) []string {
	args := []string{}

	// Non-interactive mode with streaming JSON output
	// Note: --verbose is required when using --print with --output-format stream-json
	args = append(args, "--print")
	args = append(args, "--verbose")
	args = append(args, "--output-format", "stream-json")

	// Model selection
	if req.Model != "" {
		args = append(args, "--model", req.Model)
	}

	// Permission mode based on sandbox setting
	switch req.Sandbox {
	case ai.SandboxReadOnly:
		args = append(args, "--permission-mode", "plan")
	case ai.SandboxFullAccess:
		args = append(args, "--dangerously-skip-permissions")
	case ai.SandboxWorkspaceWrite:
		args = append(args, "--permission-mode", "acceptEdits")
	default:
		args = append(args, "--permission-mode", "default")
	}

	// Session resumption
	if req.SessionID != "" {
		args = append(args, "--resume", req.SessionID)
	}

	// The prompt as the positional argument
	args = append(args, req.Prompt)

	return args
}

// streamOutput reads Claude CLI stdout and sends events to the channel.
func streamOutput(r io.Reader, events chan<- eventOrError) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		event := parseEvent(line)
		if event != nil {
			events <- eventOrError{event: event}
		}
	}

	if err := scanner.Err(); err != nil {
		events <- eventOrError{err: fmt.Errorf("read stdout: %w", err)}
	}
}

// streamErrors reads Claude CLI stderr and sends error events to the channel.
func streamErrors(r io.Reader, events chan<- eventOrError) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			events <- eventOrError{event: ai.ErrorEvent{Message: line}}
		}
	}
}

// parseEvent parses a JSON line from Claude CLI into an ai.StreamEvent.
func parseEvent(line string) ai.StreamEvent {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		// Not JSON, treat as plain text message
		return ai.TextEvent{Text: line + "\n"}
	}

	eventType, _ := raw["type"].(string)
	switch eventType {
	case "assistant", "text":
		if text, ok := raw["text"].(string); ok && text != "" {
			return ai.TextEvent{Text: text}
		}
		if content, ok := raw["content"].(string); ok && content != "" {
			return ai.TextEvent{Text: content}
		}
	case "thinking", "reasoning":
		if text, ok := raw["text"].(string); ok && text != "" {
			return ai.TextEvent{Text: "[thinking] " + text + "\n"}
		}
	case "tool_use", "tool_call":
		name, _ := raw["name"].(string)
		input, _ := raw["input"].(map[string]any)

		if strings.Contains(strings.ToLower(name), "bash") ||
			strings.Contains(strings.ToLower(name), "execute") ||
			strings.Contains(strings.ToLower(name), "command") {
			cmd, _ := input["command"].(string)
			return ai.CommandEvent{Command: cmd, Status: "running"}
		}
		if strings.Contains(strings.ToLower(name), "write") ||
			strings.Contains(strings.ToLower(name), "edit") ||
			strings.Contains(strings.ToLower(name), "file") {
			path, _ := input["path"].(string)
			if path == "" {
				path, _ = input["file_path"].(string)
			}
			return ai.FileEvent{Path: path, Action: "modify", Status: "pending"}
		}
	case "tool_result":
		if output, ok := raw["output"].(string); ok && output != "" {
			return ai.TextEvent{Text: output + "\n"}
		}
	case "error":
		msg, _ := raw["message"].(string)
		if msg == "" {
			msg, _ = raw["error"].(string)
		}
		if msg != "" {
			return ai.ErrorEvent{Message: msg}
		}
	case "result":
		if text, ok := raw["result"].(string); ok && text != "" {
			return ai.TextEvent{Text: text + "\n"}
		}
	}

	return nil
}
