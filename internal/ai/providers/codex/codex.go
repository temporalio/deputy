// Package codex provides an AI provider implementation using OpenAI's Codex CLI.
//
// Codex is a full agentic provider that can execute commands, modify files,
// and perform complex multi-step operations autonomously.
package codex

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/openai/codex"
)

func init() {
	ai.MustRegisterProvider(&Provider{})
}

// Provider implements ai.Provider using the Codex CLI.
type Provider struct{}

var _ ai.Provider = (*Provider)(nil)

// Name returns the provider identifier.
func (p *Provider) Name() string { return "codex" }

// Capabilities describes what the Codex provider can do.
func (p *Provider) Capabilities() ai.ProviderCapabilities {
	return ai.ProviderCapabilities{
		Streaming:         true,
		ToolUse:           true,
		Vision:            false,
		Agentic:           true,
		SessionResumption: true,
		MaxContextTokens:  0, // Varies by model
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
		if req.WorkDir == "" {
			yield(nil, fmt.Errorf("codex provider requires WorkDir to be set"))
			return
		}

		sandboxMode := mapSandbox(req.Sandbox)

		args := codex.Args{
			Input:            req.Prompt,
			Model:            req.Model,
			SandboxMode:      sandboxMode,
			WorkingDirectory: req.WorkDir,
			ThreadID:         req.SessionID,
			FullAuto:         req.Sandbox == ai.SandboxFullAccess,
			SkipGitRepoCheck: true,
		}

		var lastThreadID string
		var totalUsage ai.Usage
		requestedModel := req.Model // Track the model we requested (codex doesn't report back which model was used)

		for event, evtErr := range codex.Run(ctx, args) {
			if evtErr != nil {
				if !yield(nil, evtErr) {
					return
				}
				continue
			}

			// Capture thread ID for session resumption
			if event.ThreadID != "" {
				lastThreadID = event.ThreadID
			}

			// Accumulate usage from turn.completed events
			if event.Usage != nil {
				totalUsage.PromptTokens += event.Usage.InputTokens
				totalUsage.CompletionTokens += event.Usage.OutputTokens
				totalUsage.TotalTokens += event.Usage.InputTokens + event.Usage.OutputTokens
			}

			aiEvent := convertEvent(event)
			if aiEvent != nil {
				if !yield(aiEvent, nil) {
					return
				}
			}
		}

		yield(ai.DoneEvent{
			SessionID:    lastThreadID,
			FinishReason: ai.FinishReasonStop,
			Usage:        totalUsage,
			Model:        requestedModel,
		}, nil)
	}
}

// mapSandbox converts ai.Sandbox to codex.SandboxMode.
func mapSandbox(s ai.Sandbox) codex.SandboxMode {
	switch s {
	case ai.SandboxReadOnly:
		return codex.SandboxModeReadOnly
	case ai.SandboxFullAccess:
		return codex.SandboxModeDangerFullAccess
	default:
		return codex.SandboxModeWorkspaceWrite
	}
}

// convertEvent transforms a Codex SDK event into an ai.StreamEvent.
func convertEvent(event *codex.ThreadEvent) ai.StreamEvent {
	if event == nil {
		return nil
	}

	switch item := event.Item.(type) {
	case *codex.AgentMessageItem:
		text := strings.TrimSpace(item.Text)
		if text != "" {
			return ai.TextEvent{Text: text + "\n"}
		}
	case *codex.ReasoningItem:
		text := strings.TrimSpace(item.Text)
		if text != "" {
			// Emit reasoning as text with a prefix
			return ai.TextEvent{Text: "[thinking] " + text + "\n"}
		}
	case *codex.CommandExecutionItem:
		return ai.CommandEvent{
			Command:  item.Command,
			Status:   string(item.Status),
			ExitCode: item.ExitCode,
			Output:   strings.TrimSpace(item.AggregatedOutput),
		}
	case *codex.FileChangeItem:
		if len(item.Changes) > 0 {
			change := item.Changes[0]
			return ai.FileEvent{
				Path:   change.Path,
				Action: string(change.Kind),
				Status: string(item.Status),
			}
		}
	case *codex.ErrorItem:
		return ai.ErrorEvent{
			Message: strings.TrimSpace(item.Message),
		}
	}

	// Handle turn-level events for status updates
	switch event.Type {
	case codex.EventTypeThreadStarted:
		return ai.StatusEvent{Status: "connected"}
	case codex.EventTypeTurnStarted:
		return ai.StatusEvent{Status: "thinking"}
	case codex.EventTypeItemStarted:
		return ai.StatusEvent{Status: "working"}
	case codex.EventTypeTurnFailed:
		if event.Error != nil {
			return ai.ErrorEvent{
				Message: event.Error.Message,
			}
		}
	}

	return nil
}
