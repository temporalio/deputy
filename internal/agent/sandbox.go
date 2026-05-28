package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"connectrpc.com/connect"
	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
	"github.com/temporalio/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SandboxRuntime identifies the container runtime for sandboxed execution.
type SandboxRuntime string

const (
	// RuntimeDocker uses Docker for sandboxing.
	RuntimeDocker SandboxRuntime = "docker"

	// RuntimeGVisor uses gVisor (runsc) for sandboxing.
	RuntimeGVisor SandboxRuntime = "gvisor"

	// RuntimePodman uses Podman for sandboxing.
	RuntimePodman SandboxRuntime = "podman"
)

// SandboxOptions configures sandboxed plugin execution.
type SandboxOptions struct {
	// Runtime is the container runtime to use.
	Runtime SandboxRuntime

	// Image is the container image to run.
	Image string

	// NetworkMode controls network access ("none", "host", "bridge").
	NetworkMode string

	// ReadOnlyRoot makes the root filesystem read-only.
	ReadOnlyRoot bool

	// MemoryLimit is the memory limit (e.g., "512m", "2g").
	MemoryLimit string

	// CPULimit is the CPU limit (e.g., "1.0", "0.5").
	CPULimit string

	// Timeout is the maximum execution duration.
	Timeout time.Duration

	// WorkDir is the working directory to mount inside the container.
	WorkDir string

	// SocketPath is where to expose the plugin's gRPC socket.
	SocketPath string
}

// SandboxedHandler implements AgentPluginHandler by running agents in containers.
type SandboxedHandler struct {
	agentv1connect.UnimplementedAgentPluginHandler

	name string
	opts SandboxOptions
}

// NewSandboxedHandler creates a sandboxed handler for running agents in containers.
func NewSandboxedHandler(name string, opts SandboxOptions) (*SandboxedHandler, error) {
	if opts.Image == "" {
		return nil, fmt.Errorf("sandbox image is required")
	}
	if opts.Runtime == "" {
		opts.Runtime = RuntimeDocker
	}
	if opts.NetworkMode == "" {
		opts.NetworkMode = "none" // No network by default for security
	}

	return &SandboxedHandler{
		name: name,
		opts: opts,
	}, nil
}

// Ensure SandboxedHandler implements AgentPluginHandler.
var _ agentv1connect.AgentPluginHandler = (*SandboxedHandler)(nil)

// GetInfo returns metadata about the sandboxed plugin.
func (h *SandboxedHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return connect.NewResponse(&agentv1.GetInfoResponse{
		Name:        h.name,
		DisplayName: h.name + " (sandboxed)",
		Description: fmt.Sprintf("Sandboxed agent running in %s", h.opts.Runtime),
		Version:     "1.0.0",
		Capabilities: &agentv1.AgentCapabilities{
			Streaming:   true,
			Agentic:     true,
			Sandboxable: true,
		},
	}), nil
}

// Execute runs the agent in a sandboxed container.
func (h *SandboxedHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	msg := req.Msg
	sessionID := fmt.Sprintf("sandbox-%d", time.Now().UnixNano())

	// Send initializing event
	if err := stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING,
		Details: &agentv1.ExecuteEvent_Status{
			Status: &agentv1.StatusEvent{
				Status:  "starting",
				Details: "Starting sandboxed container",
			},
		},
	}); err != nil {
		return err
	}

	// Build container command
	args, err := h.buildContainerArgs(msg)
	if err != nil {
		return stream.Send(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
			Details: &agentv1.ExecuteEvent_Error{
				Error: &agentv1.ErrorEvent{
					Message:     fmt.Sprintf("invalid sandbox configuration: %v", err),
					IsFatal:     true,
					IsRetriable: false,
				},
			},
		})
	}

	cmd := exec.CommandContext(ctx, string(h.opts.Runtime), args...)
	if msg.GetWorkDir() != "" {
		cmd.Dir = msg.GetWorkDir()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return stream.Send(&agentv1.ExecuteEvent{
			SessionId: sessionID,
			Timestamp: timestamppb.Now(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
			Details: &agentv1.ExecuteEvent_Error{
				Error: &agentv1.ErrorEvent{
					Message:     fmt.Sprintf("container execution failed: %v", err),
					IsFatal:     true,
					IsRetriable: false,
				},
			},
		})
	}

	// Send output as text event
	if err := stream.Send(&agentv1.ExecuteEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
		Details: &agentv1.ExecuteEvent_Text{
			Text: &agentv1.TextEvent{
				Text: string(output),
			},
		},
	}); err != nil {
		return err
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

// buildContainerArgs constructs container runtime arguments.
func (h *SandboxedHandler) buildContainerArgs(req *agentv1.ExecuteRequest) ([]string, error) {
	args := []string{"run", "--rm"}

	// Network isolation
	args = append(args, "--network", h.opts.NetworkMode)

	// Read-only root filesystem
	if h.opts.ReadOnlyRoot {
		args = append(args, "--read-only")
	}

	// Resource limits
	if h.opts.MemoryLimit != "" {
		args = append(args, "--memory", h.opts.MemoryLimit)
	}
	if h.opts.CPULimit != "" {
		args = append(args, "--cpus", h.opts.CPULimit)
	}

	// Mount working directory
	if workDir := req.GetWorkDir(); workDir != "" {
		// Security: Validate workDir to prevent injection via volume mount
		// Reject paths with control characters or shell metacharacters
		if strings.ContainsAny(workDir, "\x00\n\r:") {
			// Colon is particularly dangerous as it separates host:container paths
			// Null/newlines could confuse argument parsing
			return nil, fmt.Errorf("invalid work directory path")
		}
		if err := sandbox.ValidatePath(workDir); err != nil {
			return nil, err
		}

		mountOpt := "ro" // Read-only by default
		sandbox := req.GetSandbox()
		if sandbox == agentv1.SandboxMode_SANDBOX_MODE_WORKSPACE_WRITE ||
			sandbox == agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS {
			mountOpt = "rw"
		}
		args = append(args, "-v", fmt.Sprintf("%s:/workspace:%s", workDir, mountOpt))
		args = append(args, "-w", "/workspace")
	}

	// Environment variables
	// Security: Sanitize values to prevent injection via environment variables
	// Newlines could be used to inject additional env vars or commands
	prompt := strings.ReplaceAll(req.GetPrompt(), "\n", "\\n")
	prompt = strings.ReplaceAll(prompt, "\r", "\\r")
	args = append(args, "-e", fmt.Sprintf("PROMPT=%s", prompt))

	if system := req.GetSystem(); system != "" {
		system = strings.ReplaceAll(system, "\n", "\\n")
		system = strings.ReplaceAll(system, "\r", "\\r")
		args = append(args, "-e", fmt.Sprintf("SYSTEM=%s", system))
	}
	if model := req.GetModel(); model != "" {
		// Model names shouldn't have newlines, but sanitize defensively
		model = strings.ReplaceAll(model, "\n", "")
		model = strings.ReplaceAll(model, "\r", "")
		args = append(args, "-e", fmt.Sprintf("MODEL=%s", model))
	}

	// Image
	args = append(args, h.opts.Image)

	return args, nil
}

// Resume continues a previous session.
func (h *SandboxedHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: req.Msg.GetSessionId(),
		Timestamp: timestamppb.Now(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
		Details: &agentv1.ExecuteEvent_Error{
			Error: &agentv1.ErrorEvent{
				Message: "session resumption not supported for sandboxed plugins",
				IsFatal: true,
			},
		},
	})
}

// Approve handles approval requests.
func (h *SandboxedHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	// Sandboxed plugins typically don't support interactive approval
	return connect.NewResponse(&agentv1.ApproveResponse{
		Accepted: false,
		Message:  "sandboxed plugins do not support interactive approval",
	}), nil
}

// Cancel requests graceful termination.
func (h *SandboxedHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	// Container termination happens via context cancellation
	return connect.NewResponse(&agentv1.CancelResponse{
		Cancelled: true,
	}), nil
}

// CheckRuntime verifies the container runtime is available.
func CheckRuntime(runtime SandboxRuntime) error {
	_, err := exec.LookPath(string(runtime))
	if err != nil {
		return fmt.Errorf("container runtime %s not found in PATH", runtime)
	}
	return nil
}

// AvailableRuntimes returns which container runtimes are available.
func AvailableRuntimes() []SandboxRuntime {
	var available []SandboxRuntime
	for _, rt := range []SandboxRuntime{RuntimeDocker, RuntimePodman, RuntimeGVisor} {
		if CheckRuntime(rt) == nil {
			available = append(available, rt)
		}
	}
	return available
}

// DefaultSandboxImage returns a suggested image for sandboxed agent execution.
func DefaultSandboxImage(agentName string) string {
	// These are placeholder image names - actual images would need to be built
	switch strings.ToLower(agentName) {
	case "claude":
		return "deputy-agent-claude:latest"
	case "codex":
		return "deputy-agent-codex:latest"
	default:
		return fmt.Sprintf("deputy-agent-%s:latest", agentName)
	}
}
