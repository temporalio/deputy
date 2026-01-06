package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"regexp"
	"strings"
)

// Session represents a stateful AI interaction with history and tools.
// Sessions enable multi-turn conversations and agentic workflows.
//
// For simple one-shot completions, use [Provider.Complete] directly.
// Use Session when you need:
//   - Conversation history
//   - Tool execution with approval workflows
//   - Agentic file/command operations
//   - Session resumption
//
// # Safety
//
// Sessions enforce safety by default via [ApprovalPolicy]. Commands and file
// writes require approval unless explicitly disabled. High-risk operations
// (rm -rf, sudo, etc.) always require approval regardless of policy.
//
// Use [DefaultApprovalPolicy] for sensible defaults, or configure a custom
// policy via [SessionConfig.Approval].
type Session struct {
	provider Provider
	config   SessionConfig
	history  []Message
	id       string
}

// SessionConfig configures a session's behavior.
type SessionConfig struct {
	// Provider is the AI provider to use.
	// Required.
	Provider Provider

	// System is the system prompt.
	System string

	// Model overrides the provider's default model.
	Model string

	// WorkDir is the working directory for agentic operations.
	WorkDir string

	// Sandbox controls file/command permissions.
	Sandbox Sandbox

	// Tools are available to the AI during this session.
	Tools []Tool

	// SessionID resumes a previous session.
	SessionID string

	// Approval controls what operations require user approval.
	// If nil, DefaultApprovalPolicy() is used.
	Approval *ApprovalPolicy

	// Guardrails defines safety constraints for AI operations.
	// If nil, DefaultGuardrails() is used.
	// Guardrails are evaluated BEFORE approval checks and can block
	// operations outright or flag them as high-risk.
	Guardrails *Guardrails

	// Hooks allow intercepting session events.
	// Hooks are called AFTER approval checks pass.
	Hooks SessionHooks
}

// ApprovalPolicy controls what operations require user approval.
// This is a first-class safety concern, not an optional feature.
type ApprovalPolicy struct {
	// Commands controls whether shell commands require approval.
	// Default: true (require approval for all commands)
	Commands ApprovalMode

	// FileWrites controls whether file writes require approval.
	// Default: true (require approval for all writes)
	FileWrites ApprovalMode

	// HighRiskAlways forces approval for high-risk operations regardless
	// of other settings. This cannot be disabled.
	// High-risk patterns: rm -rf, sudo, chmod 777, etc.
	// Default: true (always require approval for high-risk)
	HighRiskAlways bool

	// Approver is called when approval is needed.
	// Return nil to approve, error to deny.
	// If nil and approval is required, operations are denied with ErrApprovalRequired.
	Approver ApprovalFunc
}

// ApprovalMode determines how approval is handled.
type ApprovalMode int

const (
	// ApprovalRequired means the operation always requires approval.
	ApprovalRequired ApprovalMode = iota

	// ApprovalNotRequired means the operation proceeds without approval.
	// Note: High-risk operations still require approval if HighRiskAlways is true.
	ApprovalNotRequired

	// ApprovalDeny means the operation is always denied.
	ApprovalDeny
)

// ApprovalFunc is called to request user approval.
// It receives the operation type and details, returning nil to approve.
type ApprovalFunc func(op ApprovalOperation) error

// ApprovalOperation describes an operation requiring approval.
type ApprovalOperation struct {
	// Type is the operation type: "command", "file_write", "tool_call"
	Type string

	// Description is a human-readable description of the operation.
	Description string

	// Details contains operation-specific data.
	// For commands: {"command": "rm -rf /tmp"}
	// For files: {"path": "/etc/passwd", "action": "modify"}
	Details map[string]string

	// HighRisk indicates this operation matched a high-risk pattern.
	HighRisk bool
}

// ErrApprovalRequired is returned when an operation requires approval
// but no Approver is configured.
var ErrApprovalRequired = errors.New("operation requires approval")

// ErrOperationDenied is returned when an operation is denied by policy.
var ErrOperationDenied = errors.New("operation denied by policy")

// DefaultApprovalPolicy returns a safe default policy:
//   - Commands require approval
//   - File writes require approval
//   - High-risk operations always require approval
//
// This is the policy used when SessionConfig.Approval is nil.
func DefaultApprovalPolicy() *ApprovalPolicy {
	return &ApprovalPolicy{
		Commands:       ApprovalRequired,
		FileWrites:     ApprovalRequired,
		HighRiskAlways: true,
		Approver:       nil, // Caller must provide
	}
}

// AutoApprovePolicy returns a policy that auto-approves everything.
// Use with caution - this is only appropriate for:
//   - Trusted, sandboxed environments
//   - CI/CD with read-only sandbox
//   - Testing
//
// Even with AutoApprovePolicy, high-risk commands are still flagged
// (but approved if HighRiskAlways is false).
func AutoApprovePolicy() *ApprovalPolicy {
	return &ApprovalPolicy{
		Commands:       ApprovalNotRequired,
		FileWrites:     ApprovalNotRequired,
		HighRiskAlways: false,
		Approver:       func(ApprovalOperation) error { return nil },
	}
}

// highRiskPatterns matches dangerous shell commands.
var highRiskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+(-[rf]+\s+)*(/|~|\$HOME|\.\.)`),  // rm with dangerous paths
	regexp.MustCompile(`(?i)\bsudo\b`),                               // privilege escalation
	regexp.MustCompile(`(?i)\bchmod\s+[0-7]*7[0-7]*\b`),              // world-writable permissions
	regexp.MustCompile(`(?i)\bchown\s`),                              // ownership changes
	regexp.MustCompile(`(?i)\bcurl\b.*\|\s*(ba)?sh`),                 // pipe to shell
	regexp.MustCompile(`(?i)\bwget\b.*\|\s*(ba)?sh`),                 // pipe to shell
	regexp.MustCompile(`(?i)>\s*/etc/`),                              // overwrite system files
	regexp.MustCompile(`(?i)\bdd\s+.*of=/dev/`),                      // write to devices
	regexp.MustCompile(`(?i)\bmkfs\b`),                               // format filesystems
	regexp.MustCompile(`(?i):(){.*};:`),                              // fork bomb patterns
	regexp.MustCompile(`(?i)\bgit\s+push\s+.*--force`),               // force push
	regexp.MustCompile(`(?i)\bgit\s+reset\s+--hard`),                 // hard reset
}

// highRiskPaths are sensitive file paths.
var highRiskPaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers",
	"~/.ssh/", "~/.gnupg/", "~/.aws/",
	".env", ".env.local", ".env.production",
	"credentials", "secrets", "private_key",
}

// isHighRiskCommand checks if a command matches high-risk patterns.
func isHighRiskCommand(cmd string) bool {
	for _, pattern := range highRiskPatterns {
		if pattern.MatchString(cmd) {
			return true
		}
	}
	return false
}

// isHighRiskPath checks if a file path is sensitive.
func isHighRiskPath(path string) bool {
	lower := strings.ToLower(path)
	for _, sensitive := range highRiskPaths {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

// SessionHooks allow intercepting session events.
// Hooks are called AFTER approval checks pass.
type SessionHooks struct {
	// OnMessage is called for each message added to history.
	OnMessage func(msg Message)

	// OnToolCall is called before a tool is executed.
	// Return an error to block the tool call.
	OnToolCall func(call ToolCall) error

	// OnCommand is called before a shell command executes (agentic).
	// Return an error to block the command.
	OnCommand func(cmd string) error

	// OnFileWrite is called before a file is written (agentic).
	// Return an error to block the write.
	OnFileWrite func(path string) error
}

// NewSession creates a new AI session.
func NewSession(cfg SessionConfig) *Session {
	return &Session{
		provider: cfg.Provider,
		config:   cfg,
		history:  make([]Message, 0),
		id:       cfg.SessionID,
	}
}

// ID returns the session ID for resumption.
func (s *Session) ID() string {
	return s.id
}

// History returns the conversation history.
func (s *Session) History() []Message {
	return s.history
}

// Send sends a message and waits for a complete response.
func (s *Session) Send(ctx context.Context, prompt string) (*CompletionResponse, error) {
	req := s.buildRequest(prompt)

	resp, err := s.provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ai completion failed: %w", err)
	}

	// Update history
	s.addMessage(Message{Role: RoleUser, Content: prompt})
	s.addMessage(Message{Role: RoleAssistant, Content: resp.Text})

	// Update session ID if provider returned one
	if resp.SessionID != "" {
		s.id = resp.SessionID
	}

	return resp, nil
}

// Stream sends a message and streams the response.
// Commands and file writes are subject to the session's ApprovalPolicy.
func (s *Session) Stream(ctx context.Context, prompt string) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		req := s.buildRequest(prompt)

		s.addMessage(Message{Role: RoleUser, Content: prompt})

		var responseText strings.Builder

		for event, err := range s.provider.Stream(ctx, req) {
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}

			// Intercept events for approval and hooks
			switch e := event.(type) {
			case TextEvent:
				responseText.WriteString(e.Text)
			case CommandEvent:
				// Check approval policy for commands
				if err := s.checkCommandApproval(e.Command); err != nil {
					if !yield(ErrorEvent{Message: err.Error(), Err: err}, nil) {
						return
					}
					continue
				}
				// Then call hook (if configured)
				if s.config.Hooks.OnCommand != nil {
					if err := s.config.Hooks.OnCommand(e.Command); err != nil {
						if !yield(ErrorEvent{Message: err.Error(), Err: err}, nil) {
							return
						}
						continue
					}
				}
			case FileEvent:
				if e.Action == "modify" || e.Action == "create" {
					// Check approval policy for file writes
					if err := s.checkFileWriteApproval(e.Path, e.Action); err != nil {
						if !yield(ErrorEvent{Message: err.Error(), Err: err}, nil) {
							return
						}
						continue
					}
					// Then call hook (if configured)
					if s.config.Hooks.OnFileWrite != nil {
						if err := s.config.Hooks.OnFileWrite(e.Path); err != nil {
							if !yield(ErrorEvent{Message: err.Error(), Err: err}, nil) {
								return
							}
							continue
						}
					}
				}
			case ToolCallEvent:
				if s.config.Hooks.OnToolCall != nil {
					if err := s.config.Hooks.OnToolCall(e.Call); err != nil {
						if !yield(ErrorEvent{Message: err.Error(), Err: err}, nil) {
							return
						}
						continue
					}
				}
			case DoneEvent:
				if e.SessionID != "" {
					s.id = e.SessionID
				}
			}

			if !yield(event, nil) {
				return
			}
		}

		// Update history with complete response
		if text := responseText.String(); text != "" {
			s.addMessage(Message{Role: RoleAssistant, Content: text})
		}
	}
}

// approvalPolicy returns the effective approval policy.
func (s *Session) approvalPolicy() *ApprovalPolicy {
	if s.config.Approval != nil {
		return s.config.Approval
	}
	return DefaultApprovalPolicy()
}

// guardrails returns the effective guardrails configuration.
func (s *Session) guardrails() *Guardrails {
	if s.config.Guardrails != nil {
		return s.config.Guardrails
	}
	g := DefaultGuardrails()
	// Compile patterns on first use
	_ = g.Compile()
	return g
}

// checkCommandApproval checks if a command is allowed by guardrails and approval policy.
func (s *Session) checkCommandApproval(cmd string) error {
	// First, evaluate guardrails
	guardrails := s.guardrails()
	result := guardrails.EvalCommand(cmd)

	// If guardrails deny the command, return immediately
	if !result.Allowed {
		return fmt.Errorf("%w: %s", ErrOperationDenied, result.Reason)
	}

	// Get approval policy
	policy := s.approvalPolicy()

	// Determine high-risk status from guardrails or legacy patterns
	highRisk := result.HighRisk || isHighRiskCommand(cmd)

	// Determine if approval is needed
	needsApproval := false
	switch policy.Commands {
	case ApprovalDeny:
		return fmt.Errorf("%w: commands are not allowed", ErrOperationDenied)
	case ApprovalRequired:
		needsApproval = true
	case ApprovalNotRequired:
		// Only need approval if high-risk and HighRiskAlways is set
		needsApproval = highRisk && policy.HighRiskAlways
	}

	if !needsApproval {
		return nil
	}

	// Need approval - call the approver
	if policy.Approver == nil {
		return fmt.Errorf("%w: command %q", ErrApprovalRequired, cmd)
	}

	op := ApprovalOperation{
		Type:        "command",
		Description: fmt.Sprintf("Execute shell command: %s", cmd),
		Details:     map[string]string{"command": cmd},
		HighRisk:    highRisk,
	}

	return policy.Approver(op)
}

// checkFileWriteApproval checks if a file write is allowed by guardrails and approval policy.
func (s *Session) checkFileWriteApproval(path, action string) error {
	// First, evaluate guardrails
	guardrails := s.guardrails()
	result := guardrails.EvalFile(path, action, s.config.WorkDir)

	// If guardrails deny the operation, return immediately
	if !result.Allowed {
		return fmt.Errorf("%w: %s", ErrOperationDenied, result.Reason)
	}

	// Get approval policy
	policy := s.approvalPolicy()

	// Determine high-risk status from guardrails or legacy patterns
	highRisk := result.HighRisk || isHighRiskPath(path)

	// Determine if approval is needed
	needsApproval := false
	switch policy.FileWrites {
	case ApprovalDeny:
		return fmt.Errorf("%w: file writes are not allowed", ErrOperationDenied)
	case ApprovalRequired:
		needsApproval = true
	case ApprovalNotRequired:
		// Only need approval if high-risk path and HighRiskAlways is set
		needsApproval = highRisk && policy.HighRiskAlways
	}

	if !needsApproval {
		return nil
	}

	// Need approval - call the approver
	if policy.Approver == nil {
		return fmt.Errorf("%w: file write to %q", ErrApprovalRequired, path)
	}

	// Capitalize action for description (e.g., "modify" -> "Modify")
	actionTitle := action
	if len(action) > 0 {
		actionTitle = strings.ToUpper(action[:1]) + action[1:]
	}

	op := ApprovalOperation{
		Type:        "file_write",
		Description: fmt.Sprintf("%s file: %s", actionTitle, path),
		Details:     map[string]string{"path": path, "action": action},
		HighRisk:    highRisk,
	}

	return policy.Approver(op)
}

// Run executes an agentic task and returns the final result.
// This is a convenience method that streams internally and collects output.
func (s *Session) Run(ctx context.Context, prompt string) (*SessionResult, error) {
	var output strings.Builder
	var lastErr error
	var sessionID string
	var finishReason FinishReason

	// Fully drain the iterator to ensure Stream() cleanup runs
	for event, err := range s.Stream(ctx, prompt) {
		if err != nil {
			lastErr = err
			continue
		}

		switch e := event.(type) {
		case TextEvent:
			output.WriteString(e.Text)
		case ErrorEvent:
			lastErr = e.Error()
		case DoneEvent:
			sessionID = e.SessionID
			finishReason = e.FinishReason
		}
	}

	return &SessionResult{
		Success:      lastErr == nil,
		Output:       output.String(),
		SessionID:    sessionID,
		FinishReason: finishReason,
		Error:        lastErr,
	}, nil
}

// SessionResult contains the outcome of a session run.
type SessionResult struct {
	Success      bool
	Output       string
	SessionID    string
	FinishReason FinishReason
	Error        error
}

// buildRequest constructs a CompletionRequest from session state.
func (s *Session) buildRequest(prompt string) *CompletionRequest {
	return &CompletionRequest{
		Prompt:    prompt,
		System:    s.config.System,
		Model:     s.config.Model,
		Messages:  s.history,
		Tools:     s.config.Tools,
		SessionID: s.id,
		WorkDir:   s.config.WorkDir,
		Sandbox:   s.config.Sandbox,
	}
}

// addMessage adds a message to history, calling hooks if configured.
func (s *Session) addMessage(msg Message) {
	s.history = append(s.history, msg)
	if s.config.Hooks.OnMessage != nil {
		s.config.Hooks.OnMessage(msg)
	}
}

// StreamToWriter is a helper that streams session output to writers.
func StreamToWriter(ctx context.Context, s *Session, prompt string, out, errOut io.Writer) (*SessionResult, error) {
	var output strings.Builder
	var lastErr error
	var sessionID string
	var finishReason FinishReason

	for event, err := range s.Stream(ctx, prompt) {
		if err != nil {
			lastErr = err
			if errOut != nil {
				fmt.Fprintf(errOut, "error: %v\n", err)
			}
			continue
		}

		switch e := event.(type) {
		case TextEvent:
			output.WriteString(e.Text)
			if out != nil {
				fmt.Fprint(out, e.Text)
			}
		case CommandEvent:
			if out != nil {
				status := e.Status
				if e.ExitCode != nil {
					status = fmt.Sprintf("%s (exit %d)", status, *e.ExitCode)
				}
				fmt.Fprintf(out, "$ %s [%s]\n", e.Command, status)
				if e.Output != "" {
					fmt.Fprintln(out, e.Output)
				}
			}
		case FileEvent:
			if out != nil {
				fmt.Fprintf(out, "[%s] %s (%s)\n", e.Action, e.Path, e.Status)
			}
		case ErrorEvent:
			if errOut != nil {
				fmt.Fprintf(errOut, "error: %s\n", e.Message)
			}
			if lastErr == nil {
				lastErr = e.Error()
			}
		case DoneEvent:
			sessionID = e.SessionID
			finishReason = e.FinishReason
		}
	}

	return &SessionResult{
		Success:      lastErr == nil,
		Output:       output.String(),
		SessionID:    sessionID,
		FinishReason: finishReason,
		Error:        lastErr,
	}, nil
}
