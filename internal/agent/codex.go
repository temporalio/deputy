package agent

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"connectrpc.com/connect"
	"github.com/picatz/openai/codex"
	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CodexHandler implements AgentPluginHandler using the OpenAI Codex CLI.
type CodexHandler struct {
	agentv1connect.UnimplementedAgentPluginHandler
}

// NewCodexHandler creates a new Codex agent plugin handler.
func NewCodexHandler() *CodexHandler {
	return &CodexHandler{}
}

// Ensure CodexHandler implements AgentPluginHandler.
var _ agentv1connect.AgentPluginHandler = (*CodexHandler)(nil)

// Ensure CodexHandler implements Executor for in-process calls.
var _ Executor = (*CodexHandler)(nil)

// GetInfo returns metadata about the Codex plugin.
func (h *CodexHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return connect.NewResponse(&agentv1.GetInfoResponse{
		Name:        "codex",
		DisplayName: "Codex",
		Description: "OpenAI Codex CLI agent for autonomous code operations",
		Version:     "1.0.0",
		Capabilities: &agentv1.AgentCapabilities{
			Streaming:         true,
			ToolUse:           true,
			Vision:            false,
			Agentic:           true,
			SessionResumption: true,
			MaxContextTokens:  0, // Varies by model
			// Codex handles approvals inside its own CLI and never emits
			// approval-required events, so callers cannot gate its steps.
			ApprovalWorkflows: false,
		},
	}), nil
}

// Execute runs the Codex CLI with the given request and streams events.
func (h *CodexHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	msg := req.Msg
	sessionID := fmt.Sprintf("codex-%d", timestamppb.Now().GetSeconds())

	if msg.GetWorkDir() == "" {
		return h.sendError(stream, sessionID, "codex requires WorkDir to be set")
	}

	// Send initializing event
	if err := stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING,
		Details: &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{
				Status:  "initializing",
				Details: "Starting Codex agent",
			},
		},
	}); err != nil {
		return err
	}

	sandboxMode := h.mapSandbox(msg.GetSandbox())

	args := codex.Args{
		Input:            msg.GetPrompt(),
		Model:            msg.GetModel(),
		SandboxMode:      sandboxMode,
		WorkingDirectory: msg.GetWorkDir(),
		ThreadID:         msg.GetPreviousSessionId(),
		FullAuto:         msg.GetSandbox() == agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS,
		SkipGitRepoCheck: true,
	}

	var lastThreadID string
	var totalUsage agentv1.TokenUsage

	for event, evtErr := range codex.Run(ctx, args) {
		if evtErr != nil {
			if err := h.sendError(stream, sessionID, evtErr.Error()); err != nil {
				return err
			}
			continue
		}

		// Capture thread ID for session resumption
		if event.ThreadID != "" {
			lastThreadID = event.ThreadID
		}

		// Accumulate usage from turn.completed events
		if event.Usage != nil {
			totalUsage.PromptTokens += int32(event.Usage.InputTokens)
			totalUsage.CompletionTokens += int32(event.Usage.OutputTokens)
			totalUsage.TotalTokens += int32(event.Usage.InputTokens + event.Usage.OutputTokens)
		}

		protoEvent := h.convertEvent(event, sessionID)
		if protoEvent != nil {
			if err := stream.Send(protoEvent); err != nil {
				return err
			}
		}
	}

	// Send completion event
	finalSessionID := sessionID
	if lastThreadID != "" {
		finalSessionID = lastThreadID
	}

	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Details: &agentv1.ExecuteEvent_Done{
			Done: &agentv1.DoneEvent{
				SessionId: finalSessionID,
				Reason:    agentv1.DoneReason_DONE_REASON_SUCCESS,
				Usage:     &totalUsage,
			},
		},
	})
}

// Resume continues a previous Codex session.
func (h *CodexHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	msg := req.Msg

	// Convert resume request to execute request with session ID
	execReq := &agentv1.ExecuteRequest{
		Prompt:            msg.GetPrompt(),
		WorkDir:           msg.GetWorkDir(),
		PreviousSessionId: msg.GetSessionId(),
	}

	return h.Execute(ctx, connect.NewRequest(execReq), stream)
}

// Approve handles approval requests.
func (h *CodexHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	// Codex handles approval internally
	return connect.NewResponse(&agentv1.ApproveResponse{
		Accepted: true,
		Message:  "Codex handles approval internally",
	}), nil
}

// Cancel requests graceful termination.
func (h *CodexHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	// Cancellation is handled via context cancellation
	return connect.NewResponse(&agentv1.CancelResponse{
		Cancelled: true,
	}), nil
}

// mapSandbox converts proto SandboxMode to codex.SandboxMode.
func (h *CodexHandler) mapSandbox(s agentv1.SandboxMode) codex.SandboxMode {
	switch s {
	case agentv1.SandboxMode_SANDBOX_MODE_READ_ONLY:
		return codex.SandboxModeReadOnly
	case agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS:
		return codex.SandboxModeDangerFullAccess
	default:
		return codex.SandboxModeWorkspaceWrite
	}
}

// sendError sends an error event to the stream.
func (h *CodexHandler) sendError(stream *connect.ServerStream[agentv1.ExecuteEvent], sessionID, message string) error {
	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
		Details: &agentv1.ExecuteEvent_Error{
			Error: &agentv1.ErrorEvent{
				Message: message,
				IsFatal: true,
			},
		},
	})
}

// convertEvent transforms a Codex SDK event into an ExecuteEvent.
func (h *CodexHandler) convertEvent(event *codex.ThreadEvent, sessionID string) *agentv1.ExecuteEvent {
	if event == nil {
		return nil
	}

	base := &agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
	}

	switch item := event.Item.(type) {
	case *codex.AgentMessageItem:
		text := strings.TrimSpace(item.Text)
		if text != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: text + "\n"},
			}
			return base
		}

	case *codex.ReasoningItem:
		// Map reasoning to text events (proto doesn't have a separate thinking type)
		text := strings.TrimSpace(item.Text)
		if text != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: "[reasoning] " + text},
			}
			return base
		}

	case *codex.CommandExecutionItem:
		var status agentv1.CommandStatus
		switch item.Status {
		case "running":
			status = agentv1.CommandStatus_COMMAND_STATUS_RUNNING
		case "completed":
			status = agentv1.CommandStatus_COMMAND_STATUS_COMPLETED
		case "failed":
			status = agentv1.CommandStatus_COMMAND_STATUS_FAILED
		default:
			status = agentv1.CommandStatus_COMMAND_STATUS_PENDING
		}

		var exitCode int32
		if item.ExitCode != nil {
			exitCode = int32(*item.ExitCode)
		}

		base.Details = &agentv1.ExecuteEvent_Command{
			Command: &agentv1.CommandEvent{
				Command:  item.Command,
				Status:   status,
				ExitCode: exitCode,
				Stdout:   strings.TrimSpace(item.AggregatedOutput),
			},
		}
		return base

	case *codex.FileChangeItem:
		if len(item.Changes) > 0 {
			change := item.Changes[0]
			var action agentv1.FileAction
			switch change.Kind {
			case "create":
				action = agentv1.FileAction_FILE_ACTION_CREATE
			case "modify":
				action = agentv1.FileAction_FILE_ACTION_MODIFY
			case "delete":
				action = agentv1.FileAction_FILE_ACTION_DELETE
			default:
				action = agentv1.FileAction_FILE_ACTION_MODIFY
			}

			var fileStatus agentv1.FileStatus
			switch item.Status {
			case "pending":
				fileStatus = agentv1.FileStatus_FILE_STATUS_PENDING
			case "completed":
				fileStatus = agentv1.FileStatus_FILE_STATUS_COMPLETED
			case "failed":
				fileStatus = agentv1.FileStatus_FILE_STATUS_FAILED
			default:
				fileStatus = agentv1.FileStatus_FILE_STATUS_PENDING
			}

			base.Details = &agentv1.ExecuteEvent_File{
				File: &agentv1.FileEvent{
					Path:   change.Path,
					Action: action,
					Status: fileStatus,
				},
			}
			return base
		}

	case *codex.ErrorItem:
		base.Phase = agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED
		base.Details = &agentv1.ExecuteEvent_Error{
			Error: &agentv1.ErrorEvent{
				Message: strings.TrimSpace(item.Message),
				IsFatal: true,
			},
		}
		return base
	}

	// Handle turn-level events for status updates
	switch event.Type {
	case codex.EventTypeThreadStarted:
		base.Details = &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{Status: "connected"},
		}
		return base
	case codex.EventTypeTurnStarted:
		base.Details = &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{Status: "thinking"},
		}
		return base
	case codex.EventTypeItemStarted:
		base.Details = &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{Status: "working"},
		}
		return base
	case codex.EventTypeTurnFailed:
		if event.Error != nil {
			base.Phase = agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED
			base.Details = &agentv1.ExecuteEvent_Error{
				Error: &agentv1.ErrorEvent{
					Message: event.Error.Message,
					IsFatal: true,
				},
			}
			return base
		}
	}

	return nil
}

// ExecuteIter implements Executor for in-process execution without a connect.ServerStream.
func (h *CodexHandler) ExecuteIter(ctx context.Context, req *agentv1.ExecuteRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(yield func(*agentv1.ExecuteEvent, error) bool) {
		sessionID := fmt.Sprintf("codex-%d", timestamppb.Now().GetSeconds())

		if req.GetWorkDir() == "" {
			yield(nil, fmt.Errorf("codex requires WorkDir to be set"))
			return
		}

		// Send initializing event
		if !yield(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING,
			Details: &agentv1.ExecuteEvent_Status{
				Status: &agentv1.StatusEvent{
					Status:  "initializing",
					Details: "Starting Codex agent",
				},
			},
		}, nil) {
			return
		}

		sandboxMode := h.mapSandbox(req.GetSandbox())

		args := codex.Args{
			Input:            req.GetPrompt(),
			Model:            req.GetModel(),
			SandboxMode:      sandboxMode,
			WorkingDirectory: req.GetWorkDir(),
			ThreadID:         req.GetPreviousSessionId(),
			FullAuto:         req.GetSandbox() == agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS,
			SkipGitRepoCheck: true,
		}

		var lastThreadID string
		var totalUsage agentv1.TokenUsage

		for event, evtErr := range codex.Run(ctx, args) {
			if evtErr != nil {
				// Yield error event but continue
				if !yield(&agentv1.ExecuteEvent{
					SessionId: sessionID,
					Timestamp: timestamppb.Now(),
					Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
					Details: &agentv1.ExecuteEvent_Error{
						Error: &agentv1.ErrorEvent{
							Message: evtErr.Error(),
							IsFatal: false,
						},
					},
				}, nil) {
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
				totalUsage.PromptTokens += int32(event.Usage.InputTokens)
				totalUsage.CompletionTokens += int32(event.Usage.OutputTokens)
				totalUsage.TotalTokens += int32(event.Usage.InputTokens + event.Usage.OutputTokens)
			}

			protoEvent := h.convertEvent(event, sessionID)
			if protoEvent != nil {
				if !yield(protoEvent, nil) {
					return
				}
			}
		}

		// Send completion event
		finalSessionID := sessionID
		if lastThreadID != "" {
			finalSessionID = lastThreadID
		}

		yield(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
			Details: &agentv1.ExecuteEvent_Done{
				Done: &agentv1.DoneEvent{
					SessionId: finalSessionID,
					Reason:    agentv1.DoneReason_DONE_REASON_SUCCESS,
					Usage:     &totalUsage,
				},
			},
		}, nil)
	}
}

// ResumeIter implements Executor for resuming sessions without a connect.ServerStream.
func (h *CodexHandler) ResumeIter(ctx context.Context, req *agentv1.ResumeRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	// Convert resume request to execute request with session ID
	execReq := &agentv1.ExecuteRequest{
		Prompt:            req.GetPrompt(),
		WorkDir:           req.GetWorkDir(),
		PreviousSessionId: req.GetSessionId(),
	}

	return h.ExecuteIter(ctx, execReq)
}
