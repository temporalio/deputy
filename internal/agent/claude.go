package agent

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

	"connectrpc.com/connect"
	agentv1 "github.com/picatz/deputy/gen/deputy/agent/v1"
	"github.com/picatz/deputy/gen/deputy/agent/v1/agentv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ClaudeHandler implements AgentPluginHandler using the Claude CLI.
type ClaudeHandler struct {
	agentv1connect.UnimplementedAgentPluginHandler
}

// NewClaudeHandler creates a new Claude agent plugin handler.
func NewClaudeHandler() *ClaudeHandler {
	return &ClaudeHandler{}
}

// Ensure ClaudeHandler implements AgentPluginHandler.
var _ agentv1connect.AgentPluginHandler = (*ClaudeHandler)(nil)

// Ensure ClaudeHandler implements Executor for in-process calls.
var _ Executor = (*ClaudeHandler)(nil)

// GetInfo returns metadata about the Claude plugin.
func (h *ClaudeHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return connect.NewResponse(&agentv1.GetInfoResponse{
		Name:        "claude",
		DisplayName: "Claude",
		Description: "Anthropic Claude CLI agent for autonomous code operations",
		Version:     "1.0.0",
		Capabilities: &agentv1.AgentCapabilities{
			Streaming:         true,
			ToolUse:           true,
			Vision:            true,
			Agentic:           true,
			SessionResumption: true,
			MaxContextTokens:  200000,
		},
	}), nil
}

// Execute runs the Claude CLI with the given request and streams events.
func (h *ClaudeHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	msg := req.Msg
	sessionID := fmt.Sprintf("claude-%d", timestamppb.Now().GetSeconds())

	// Send initializing event
	if err := stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING,
		Details: &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{
				Status:  "initializing",
				Details: "Starting Claude agent",
			},
		},
	}); err != nil {
		return err
	}

	// Build CLI arguments
	args := h.buildArgs(msg)

	cmd := exec.CommandContext(ctx, "claude", args...)
	if msg.GetWorkDir() != "" {
		cmd.Dir = msg.GetWorkDir()
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return h.sendError(stream, sessionID, fmt.Sprintf("create stdout pipe: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return h.sendError(stream, sessionID, fmt.Sprintf("create stderr pipe: %v", err))
	}

	if err := cmd.Start(); err != nil {
		return h.sendError(stream, sessionID, fmt.Sprintf("start claude: %v", err))
	}

	// Stream events from stdout/stderr
	events := make(chan *agentv1.ExecuteEvent, 100)
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		h.streamOutput(stdout, sessionID, events, errs)
	}()
	go func() {
		defer wg.Done()
		h.streamErrors(stderr, sessionID, events)
	}()

	// Close events channel when both goroutines complete
	go func() {
		wg.Wait()
		close(events)
		close(errs)
	}()

	// Send events to the stream
	for event := range events {
		if err := stream.Send(event); err != nil {
			cmd.Process.Kill()
			return err
		}
	}

	// Check for errors from streaming
	for err := range errs {
		if err != nil {
			return h.sendError(stream, sessionID, err.Error())
		}
	}

	// Wait for command to complete
	cmdErr := cmd.Wait()
	success := cmd.ProcessState != nil && cmd.ProcessState.Success()

	if cmdErr != nil && !success {
		return h.sendError(stream, sessionID, cmdErr.Error())
	}

	// Send completion event
	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Details: &agentv1.ExecuteEvent_Done{
			Done: &agentv1.DoneEvent{
				SessionId: sessionID,
				Reason:    agentv1.DoneReason_DONE_REASON_SUCCESS,
			},
		},
	})
}

// Resume continues a previous Claude session.
func (h *ClaudeHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
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
func (h *ClaudeHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	// Claude CLI handles approval internally via CLI prompts
	return connect.NewResponse(&agentv1.ApproveResponse{
		Accepted: true,
		Message:  "Claude handles approval internally",
	}), nil
}

// Cancel requests graceful termination.
func (h *ClaudeHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	// Cancellation is handled via context cancellation
	return connect.NewResponse(&agentv1.CancelResponse{
		Cancelled: true,
	}), nil
}

// buildArgs constructs the command line arguments for the Claude CLI.
func (h *ClaudeHandler) buildArgs(req *agentv1.ExecuteRequest) []string {
	args := []string{}

	// Non-interactive mode with streaming JSON output
	args = append(args, "--print")
	args = append(args, "--verbose")
	args = append(args, "--output-format", "stream-json")

	// Model selection
	if req.GetModel() != "" {
		args = append(args, "--model", req.GetModel())
	}

	// Permission mode based on sandbox setting
	switch req.GetSandbox() {
	case agentv1.SandboxMode_SANDBOX_MODE_READ_ONLY:
		args = append(args, "--permission-mode", "plan")
	case agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS:
		args = append(args, "--dangerously-skip-permissions")
	case agentv1.SandboxMode_SANDBOX_MODE_WORKSPACE_WRITE:
		args = append(args, "--permission-mode", "acceptEdits")
	default:
		args = append(args, "--permission-mode", "default")
	}

	// Session resumption
	if req.GetPreviousSessionId() != "" {
		args = append(args, "--resume", req.GetPreviousSessionId())
	}

	// The prompt as the positional argument
	args = append(args, req.GetPrompt())

	return args
}

// sendError sends an error event to the stream.
func (h *ClaudeHandler) sendError(stream *connect.ServerStream[agentv1.ExecuteEvent], sessionID, message string) error {
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

// streamOutput reads Claude CLI stdout and sends events to the channel.
func (h *ClaudeHandler) streamOutput(r io.Reader, sessionID string, events chan<- *agentv1.ExecuteEvent, errs chan<- error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		event := h.parseEvent(line, sessionID)
		if event != nil {
			events <- event
		}
	}

	if err := scanner.Err(); err != nil {
		errs <- fmt.Errorf("read stdout: %w", err)
	}
}

// streamErrors reads Claude CLI stderr and sends error events to the channel.
func (h *ClaudeHandler) streamErrors(r io.Reader, sessionID string, events chan<- *agentv1.ExecuteEvent) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			events <- &agentv1.ExecuteEvent{
				SessionId: sessionID,
				Timestamp: timestamppb.Now(),
				Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
				Details: &agentv1.ExecuteEvent_Error{
					Error: &agentv1.ErrorEvent{
						Message: line,
						IsFatal: false,
					},
				},
			}
		}
	}
}

// parseEvent parses a JSON line from Claude CLI into an ExecuteEvent.
func (h *ClaudeHandler) parseEvent(line string, sessionID string) *agentv1.ExecuteEvent {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		// Not JSON, treat as plain text message
		return &agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
			Details: &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{
					Text: line + "\n",
				},
			},
		}
	}

	eventType, _ := raw["type"].(string)
	base := &agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
	}

	switch eventType {
	case "assistant", "text":
		text := ""
		if t, ok := raw["text"].(string); ok && t != "" {
			text = t
		} else if c, ok := raw["content"].(string); ok && c != "" {
			text = c
		}
		if text != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: text},
			}
			return base
		}

	case "thinking", "reasoning":
		// Map thinking/reasoning to text events (proto doesn't have a separate thinking type)
		if text, ok := raw["text"].(string); ok && text != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: "[thinking] " + text},
			}
			return base
		}

	case "tool_use", "tool_call":
		name, _ := raw["name"].(string)
		input, _ := raw["input"].(map[string]any)

		if strings.Contains(strings.ToLower(name), "bash") ||
			strings.Contains(strings.ToLower(name), "execute") ||
			strings.Contains(strings.ToLower(name), "command") {
			cmd, _ := input["command"].(string)
			base.Details = &agentv1.ExecuteEvent_Command{
				Command: &agentv1.CommandEvent{
					Command: cmd,
					Status:  agentv1.CommandStatus_COMMAND_STATUS_RUNNING,
				},
			}
			return base
		}

		if strings.Contains(strings.ToLower(name), "write") ||
			strings.Contains(strings.ToLower(name), "edit") ||
			strings.Contains(strings.ToLower(name), "file") {
			path, _ := input["path"].(string)
			if path == "" {
				path, _ = input["file_path"].(string)
			}
			base.Details = &agentv1.ExecuteEvent_File{
				File: &agentv1.FileEvent{
					Path:   path,
					Action: agentv1.FileAction_FILE_ACTION_MODIFY,
					Status: agentv1.FileStatus_FILE_STATUS_PENDING,
				},
			}
			return base
		}

	case "tool_result":
		if output, ok := raw["output"].(string); ok && output != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: output + "\n"},
			}
			return base
		}

	case "error":
		msg, _ := raw["message"].(string)
		if msg == "" {
			msg, _ = raw["error"].(string)
		}
		if msg != "" {
			base.Phase = agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED
			base.Details = &agentv1.ExecuteEvent_Error{
				Error: &agentv1.ErrorEvent{Message: msg, IsFatal: true},
			}
			return base
		}

	case "result":
		if text, ok := raw["result"].(string); ok && text != "" {
			base.Details = &agentv1.ExecuteEvent_Text{
				Text: &agentv1.TextEvent{Text: text + "\n"},
			}
			return base
		}
	}

	return nil
}

// ExecuteIter implements Executor for in-process execution without a connect.ServerStream.
func (h *ClaudeHandler) ExecuteIter(ctx context.Context, req *agentv1.ExecuteRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(yield func(*agentv1.ExecuteEvent, error) bool) {
		sessionID := fmt.Sprintf("claude-%d", timestamppb.Now().GetSeconds())

		// Send initializing event
		if !yield(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING,
			Details: &agentv1.ExecuteEvent_Status{
				Status: &agentv1.StatusEvent{
					Status:  "initializing",
					Details: "Starting Claude agent",
				},
			},
		}, nil) {
			return
		}

		// Build CLI arguments
		args := h.buildArgs(req)

		cmd := exec.CommandContext(ctx, "claude", args...)
		if req.GetWorkDir() != "" {
			cmd.Dir = req.GetWorkDir()
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

		// Stream events from stdout/stderr
		events := make(chan *agentv1.ExecuteEvent, 100)
		errs := make(chan error, 2)
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			h.streamOutput(stdout, sessionID, events, errs)
		}()
		go func() {
			defer wg.Done()
			h.streamErrors(stderr, sessionID, events)
		}()

		// Close events channel when both goroutines complete
		go func() {
			wg.Wait()
			close(events)
			close(errs)
		}()

		// Yield events
		for event := range events {
			if !yield(event, nil) {
				cmd.Process.Kill()
				return
			}
		}

		// Check for streaming errors
		for err := range errs {
			if err != nil {
				yield(nil, err)
				return
			}
		}

		// Wait for command to complete
		cmdErr := cmd.Wait()
		success := cmd.ProcessState != nil && cmd.ProcessState.Success()

		if cmdErr != nil && !success {
			yield(nil, cmdErr)
			return
		}

		// Send completion event
		yield(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
			Details: &agentv1.ExecuteEvent_Done{
				Done: &agentv1.DoneEvent{
					SessionId: sessionID,
					Reason:    agentv1.DoneReason_DONE_REASON_SUCCESS,
				},
			},
		}, nil)
	}
}

// ResumeIter implements Executor for resuming sessions without a connect.ServerStream.
func (h *ClaudeHandler) ResumeIter(ctx context.Context, req *agentv1.ResumeRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	// Convert resume request to execute request with session ID
	execReq := &agentv1.ExecuteRequest{
		Prompt:            req.GetPrompt(),
		WorkDir:           req.GetWorkDir(),
		PreviousSessionId: req.GetSessionId(),
	}

	return h.ExecuteIter(ctx, execReq)
}
