package sandbox

import (
	"context"
	"log/slog"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

// AuditEvent represents a sandbox audit log entry.
type AuditEvent struct {
	// Timestamp when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// EventType categorizes the audit event
	EventType AuditEventType `json:"event_type"`

	// ExecutionID is the unique identifier for the sandbox execution
	ExecutionID string `json:"execution_id"`

	// Runtime is the sandbox runtime used
	Runtime sandboxv1.Runtime `json:"runtime"`

	// Command being executed (first element only for security)
	Command string `json:"command,omitempty"`

	// CommandArgs is the number of arguments (not the args themselves)
	CommandArgCount int `json:"command_arg_count,omitempty"`

	// WorkspaceDir is the workspace directory if specified
	WorkspaceDir string `json:"workspace_dir,omitempty"`

	// NetworkMode indicates the network configuration
	NetworkMode string `json:"network_mode,omitempty"`

	// FilesystemMode indicates the filesystem access mode
	FilesystemMode string `json:"filesystem_mode,omitempty"`

	// User running the sandbox (UID:GID)
	User string `json:"user,omitempty"`

	// ExitCode if the execution completed
	ExitCode *int32 `json:"exit_code,omitempty"`

	// Duration of the execution
	DurationMs int64 `json:"duration_ms,omitempty"`

	// Error message if the event represents a failure
	Error string `json:"error,omitempty"`

	// SecurityEvent indicates if this is a security-relevant event
	SecurityEvent bool `json:"security_event,omitempty"`

	// FilteredEnvVars lists environment variables that were filtered
	FilteredEnvVars []string `json:"filtered_env_vars,omitempty"`

	// PolicyDenied indicates if a policy denied the operation
	PolicyDenied bool `json:"policy_denied,omitempty"`

	// PolicyName is the name of the policy that denied the operation
	PolicyName string `json:"policy_name,omitempty"`
}

// AuditEventType categorizes audit events.
type AuditEventType string

const (
	// AuditEventExecutionRequested is logged when execution is requested
	AuditEventExecutionRequested AuditEventType = "execution_requested"

	// AuditEventExecutionStarted is logged when execution begins
	AuditEventExecutionStarted AuditEventType = "execution_started"

	// AuditEventExecutionCompleted is logged when execution finishes
	AuditEventExecutionCompleted AuditEventType = "execution_completed"

	// AuditEventExecutionFailed is logged when execution fails
	AuditEventExecutionFailed AuditEventType = "execution_failed"

	// AuditEventPolicyDenied is logged when a policy blocks execution
	AuditEventPolicyDenied AuditEventType = "policy_denied"

	// AuditEventEnvFiltered is logged when environment variables are filtered
	AuditEventEnvFiltered AuditEventType = "env_filtered"

	// AuditEventPathBlocked is logged when a path access is blocked
	AuditEventPathBlocked AuditEventType = "path_blocked"

	// AuditEventCommandBlocked is logged when a command is blocked
	AuditEventCommandBlocked AuditEventType = "command_blocked"

	// AuditEventResourceLimitExceeded is logged when resource limits are hit
	AuditEventResourceLimitExceeded AuditEventType = "resource_limit_exceeded"

	// AuditEventCleanupFailed is logged when cleanup fails
	AuditEventCleanupFailed AuditEventType = "cleanup_failed"
)

// Auditor handles sandbox audit logging.
type Auditor struct {
	logger *slog.Logger
}

// NewAuditor creates a new auditor with the given logger.
// If logger is nil, uses the default slog logger.
func NewAuditor(logger *slog.Logger) *Auditor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Auditor{logger: logger}
}

// Log records an audit event.
func (a *Auditor) Log(ctx context.Context, event AuditEvent) {
	event.Timestamp = time.Now()

	level := slog.LevelInfo
	if event.SecurityEvent || event.PolicyDenied {
		level = slog.LevelWarn
	}
	if event.Error != "" {
		level = slog.LevelError
	}

	attrs := []slog.Attr{
		slog.String("event_type", string(event.EventType)),
		slog.String("execution_id", event.ExecutionID),
		slog.String("runtime", event.Runtime.String()),
	}

	if event.Command != "" {
		attrs = append(attrs, slog.String("command", event.Command))
	}
	if event.CommandArgCount > 0 {
		attrs = append(attrs, slog.Int("command_arg_count", event.CommandArgCount))
	}
	if event.WorkspaceDir != "" {
		attrs = append(attrs, slog.String("workspace_dir", event.WorkspaceDir))
	}
	if event.NetworkMode != "" {
		attrs = append(attrs, slog.String("network_mode", event.NetworkMode))
	}
	if event.FilesystemMode != "" {
		attrs = append(attrs, slog.String("filesystem_mode", event.FilesystemMode))
	}
	if event.User != "" {
		attrs = append(attrs, slog.String("user", event.User))
	}
	if event.ExitCode != nil {
		attrs = append(attrs, slog.Int("exit_code", int(*event.ExitCode)))
	}
	if event.DurationMs > 0 {
		attrs = append(attrs, slog.Int64("duration_ms", event.DurationMs))
	}
	if event.Error != "" {
		attrs = append(attrs, slog.String("error", event.Error))
	}
	if event.SecurityEvent {
		attrs = append(attrs, slog.Bool("security_event", true))
	}
	if len(event.FilteredEnvVars) > 0 {
		attrs = append(attrs, slog.Any("filtered_env_vars", event.FilteredEnvVars))
	}
	if event.PolicyDenied {
		attrs = append(attrs, slog.Bool("policy_denied", true))
		if event.PolicyName != "" {
			attrs = append(attrs, slog.String("policy_name", event.PolicyName))
		}
	}

	a.logger.LogAttrs(ctx, level, "sandbox_audit", attrs...)
}

// LogExecutionRequested logs when a sandbox execution is requested.
func (a *Auditor) LogExecutionRequested(ctx context.Context, executionID string, runtime sandboxv1.Runtime, req *sandboxv1.ExecuteRequest) {
	cmd := ""
	argCount := 0
	if len(req.GetCommand()) > 0 {
		cmd = req.GetCommand()[0]
		argCount = len(req.GetCommand()) - 1
	}

	networkMode := "none"
	if req.GetConfig() != nil {
		networkMode = req.GetConfig().GetNetworkMode().String()
	}

	fsMode := "unspecified"
	if req.GetConfig() != nil {
		fsMode = req.GetConfig().GetMode().String()
	}

	a.Log(ctx, AuditEvent{
		EventType:       AuditEventExecutionRequested,
		ExecutionID:     executionID,
		Runtime:         runtime,
		Command:         cmd,
		CommandArgCount: argCount,
		WorkspaceDir:    req.GetWorkspaceDir(),
		NetworkMode:     networkMode,
		FilesystemMode:  fsMode,
	})
}

// LogExecutionStarted logs when a sandbox execution actually starts.
func (a *Auditor) LogExecutionStarted(ctx context.Context, executionID string, runtime sandboxv1.Runtime) {
	a.Log(ctx, AuditEvent{
		EventType:   AuditEventExecutionStarted,
		ExecutionID: executionID,
		Runtime:     runtime,
	})
}

// LogExecutionCompleted logs when a sandbox execution completes.
func (a *Auditor) LogExecutionCompleted(ctx context.Context, executionID string, runtime sandboxv1.Runtime, exitCode int32, durationMs int64) {
	a.Log(ctx, AuditEvent{
		EventType:   AuditEventExecutionCompleted,
		ExecutionID: executionID,
		Runtime:     runtime,
		ExitCode:    &exitCode,
		DurationMs:  durationMs,
	})
}

// LogExecutionFailed logs when a sandbox execution fails.
func (a *Auditor) LogExecutionFailed(ctx context.Context, executionID string, runtime sandboxv1.Runtime, err error) {
	a.Log(ctx, AuditEvent{
		EventType:   AuditEventExecutionFailed,
		ExecutionID: executionID,
		Runtime:     runtime,
		Error:       err.Error(),
	})
}

// LogPolicyDenied logs when a policy denies a sandbox operation.
func (a *Auditor) LogPolicyDenied(ctx context.Context, executionID string, runtime sandboxv1.Runtime, policyName, reason string) {
	a.Log(ctx, AuditEvent{
		EventType:     AuditEventPolicyDenied,
		ExecutionID:   executionID,
		Runtime:       runtime,
		PolicyDenied:  true,
		PolicyName:    policyName,
		Error:         reason,
		SecurityEvent: true,
	})
}

// LogEnvFiltered logs when environment variables are filtered.
func (a *Auditor) LogEnvFiltered(ctx context.Context, executionID string, runtime sandboxv1.Runtime, filtered []string) {
	if len(filtered) == 0 {
		return
	}
	a.Log(ctx, AuditEvent{
		EventType:       AuditEventEnvFiltered,
		ExecutionID:     executionID,
		Runtime:         runtime,
		FilteredEnvVars: filtered,
	})
}

// LogPathBlocked logs when a path access is blocked.
func (a *Auditor) LogPathBlocked(ctx context.Context, executionID string, runtime sandboxv1.Runtime, path, reason string) {
	a.Log(ctx, AuditEvent{
		EventType:     AuditEventPathBlocked,
		ExecutionID:   executionID,
		Runtime:       runtime,
		WorkspaceDir:  path,
		Error:         reason,
		SecurityEvent: true,
	})
}

// LogCommandBlocked logs when a command is blocked.
func (a *Auditor) LogCommandBlocked(ctx context.Context, executionID string, runtime sandboxv1.Runtime, command, reason string) {
	a.Log(ctx, AuditEvent{
		EventType:     AuditEventCommandBlocked,
		ExecutionID:   executionID,
		Runtime:       runtime,
		Command:       command,
		Error:         reason,
		SecurityEvent: true,
	})
}

// LogCleanupFailed logs when sandbox cleanup fails.
func (a *Auditor) LogCleanupFailed(ctx context.Context, executionID string, runtime sandboxv1.Runtime, err error) {
	a.Log(ctx, AuditEvent{
		EventType:   AuditEventCleanupFailed,
		ExecutionID: executionID,
		Runtime:     runtime,
		Error:       err.Error(),
	})
}
