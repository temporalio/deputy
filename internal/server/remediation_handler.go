package server

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
	"github.com/temporalio/deputy/gen/deputy/remediation/v1/remediationv1connect"
	"github.com/temporalio/deputy/internal/agent"
	"github.com/temporalio/deputy/internal/logs"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/remediation"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// validateRequest validates a proto message using protovalidate and returns a connect error if validation fails.
func validateRequest(msg proto.Message) error {
	if err := internalproto.Validate(msg); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return nil
}

// RemediationHandler implements the RemediationService ConnectRPC service.
type RemediationHandler struct {
	remediationv1connect.UnimplementedRemediationServiceHandler

	// localMode skips security validation for in-process usage.
	// When false (remote server), ExecutePlan is disabled for security.
	localMode bool

	// registry is the agent plugin registry (defaults to agent.DefaultRegistry)
	registry *agent.Registry

	// sessions tracks active agent sessions for approval and cancellation
	sessions   map[string]*agentSession
	sessionsMu sync.RWMutex
}

// agentSession tracks an active agent execution for approval handling.
type agentSession struct {
	handler    agentv1connect.AgentPluginHandler
	cancelFunc context.CancelFunc
	approvals  chan *agentv1.ApproveRequest
}

// Ensure RemediationHandler implements the RemediationServiceHandler interface.
var _ remediationv1connect.RemediationServiceHandler = (*RemediationHandler)(nil)

// RemediationHandlerOption configures a RemediationHandler.
type RemediationHandlerOption func(*RemediationHandler)

// WithRemediationLocalMode enables local mode which allows plan execution.
// Use this for in-process clients that need to execute remediation steps.
// SECURITY: Never enable this for remote servers - it allows arbitrary code execution.
func WithRemediationLocalMode() RemediationHandlerOption {
	return func(h *RemediationHandler) {
		h.localMode = true
	}
}

// WithRemediationRegistry sets a custom agent registry.
func WithRemediationRegistry(registry *agent.Registry) RemediationHandlerOption {
	return func(h *RemediationHandler) {
		h.registry = registry
	}
}

// NewRemediationHandler creates a new RemediationHandler.
func NewRemediationHandler(opts ...RemediationHandlerOption) *RemediationHandler {
	h := &RemediationHandler{
		registry: agent.DefaultRegistry,
		sessions: make(map[string]*agentSession),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// NewRemediationHandlerWithRegistry creates a RemediationHandler with a custom registry.
// Deprecated: Use NewRemediationHandler(WithRemediationRegistry(r)) instead.
func NewRemediationHandlerWithRegistry(registry *agent.Registry) *RemediationHandler {
	return NewRemediationHandler(WithRemediationRegistry(registry))
}

// GeneratePlan creates a remediation plan from scan results.
func (h *RemediationHandler) GeneratePlan(
	ctx context.Context,
	req *connect.Request[remediationv1.GeneratePlanRequest],
) (*connect.Response[remediationv1.GeneratePlanResponse], error) {
	// Get scan result from the oneof source
	scanResult := req.Msg.GetScanResult()
	if scanResult == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("scan_result is required"))
	}

	findings := scanResult.GetFindings()
	if len(findings) == 0 {
		// No findings means no remediation needed
		return connect.NewResponse(&remediationv1.GeneratePlanResponse{
			Plan: &remediationv1.Plan{
				Id:          generatePlanID(),
				Steps:       nil,
				GeneratedAt: timestamppb.Now(),
			},
		}), nil
	}

	logs.Info(ctx, "generating remediation plan", "findings", len(findings))

	// Convert proto findings to internal vulnerability.Consolidated
	consolidated := make([]vulnerability.Consolidated, 0, len(findings))
	for _, f := range findings {
		pkg := f.GetPackage()
		advisory := f.GetAdvisory()
		if pkg == nil || advisory == nil {
			continue
		}
		c := vulnerability.Consolidated{
			PrimaryID:     advisory.GetId(),
			Package:       pkg.GetName(),
			Version:       pkg.GetVersion(),
			Ecosystem:     pkg.GetEcosystem(),
			IsDirect:      pkg.GetDirect(),
			FixedVersions: advisory.GetFixedVersions(),
		}
		consolidated = append(consolidated, c)
	}

	// Generate remediation commands
	commands, stdlibVersion := remediation.CommandsFromConsolidated(consolidated)
	commands = remediation.ApplyGuidance(commands, remediation.APIGuidance())

	// Convert to proto steps
	steps := internalproto.RemediationCommandsToSteps(commands)

	// Build the plan
	plan := &remediationv1.Plan{
		Id:            generatePlanID(),
		Steps:         steps,
		StdlibUpgrade: stdlibVersion,
		GeneratedAt:   timestamppb.Now(),
	}

	// Build response
	response := &remediationv1.GeneratePlanResponse{
		Plan:        plan,
		GeneratedAt: timestamppb.Now(),
	}

	logs.Info(ctx, "remediation plan generated",
		"plan_id", plan.Id,
		"steps", len(steps),
	)

	return connect.NewResponse(response), nil
}

// ExecutePlan applies a previously generated remediation plan.
//
// SECURITY: This method executes shell commands on the local filesystem.
// It is only available in local mode (in-process clients). Remote servers
// MUST NOT enable local mode, as this would allow arbitrary code execution.
func (h *RemediationHandler) ExecutePlan(
	ctx context.Context,
	req *connect.Request[remediationv1.ExecutePlanRequest],
	stream *connect.ServerStream[remediationv1.ExecutionEvent],
) error {
	// Security: ExecutePlan is only allowed in local mode
	if !h.localMode {
		return connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("ExecutePlan is not available on remote servers; use local CLI or daemon mode"))
	}

	plan := req.Msg.GetPlan()
	if plan == nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("plan is required"))
	}

	targetPath := req.Msg.GetTargetPath()
	if targetPath == "" {
		targetPath = "."
	}

	// Resolve to absolute path
	absWorkDir, err := resolveWorkDir(targetPath)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid work directory: %w", err))
	}

	logs.Info(ctx, "executing remediation plan",
		"plan_id", plan.GetId(),
		"steps", len(plan.GetSteps()),
		"work_dir", absWorkDir,
	)

	// Send preparing phase
	if err := stream.Send(&remediationv1.ExecutionEvent{
		Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_PREPARING,
		Message:   "Preparing to execute plan...",
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	steps := plan.GetSteps()
	if len(steps) == 0 {
		// No steps to execute
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
			Message:   "No steps to execute",
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
		return nil
	}

	// Execute each step
	for i, step := range steps {
		stepID := step.GetId()
		if stepID == "" {
			stepID = fmt.Sprintf("step-%d", i+1)
		}

		// Send step starting event
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
			StepId:    stepID,
			Message:   fmt.Sprintf("Executing step %d/%d: %s", i+1, len(steps), step.GetTitle()),
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}

		// Execute the step
		output, execErr := executeStep(ctx, absWorkDir, step)

		if execErr != nil {
			// Send failure event with output in message
			failMsg := fmt.Sprintf("Step failed: %v", execErr)
			if output != "" {
				failMsg = fmt.Sprintf("Step failed: %v\n%s", execErr, output)
			}
			if err := stream.Send(&remediationv1.ExecutionEvent{
				Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
				StepId:    stepID,
				Message:   failMsg,
				Timestamp: timestamppb.Now(),
			}); err != nil {
				return err
			}
			// Return the error to stop execution
			return connect.NewError(connect.CodeInternal, fmt.Errorf("step %s failed: %w", stepID, execErr))
		}

		// Send step completed event
		completeMsg := fmt.Sprintf("Completed step %d/%d", i+1, len(steps))
		if output != "" {
			completeMsg = fmt.Sprintf("Completed step %d/%d\n%s", i+1, len(steps), output)
		}
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
			StepId:    stepID,
			Message:   completeMsg,
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
	}

	// Send completion event
	if err := stream.Send(&remediationv1.ExecutionEvent{
		Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Message:   fmt.Sprintf("Successfully executed %d steps", len(steps)),
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	logs.Info(ctx, "remediation plan executed successfully",
		"plan_id", plan.GetId(),
		"steps_executed", len(steps),
	)

	return nil
}

// resolveWorkDir resolves and validates the working directory.
func resolveWorkDir(dir string) (string, error) {
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", absPath)
	}
	return absPath, nil
}

// executeStep runs a single remediation step and returns output.
func executeStep(ctx context.Context, workDir string, step *remediationv1.Step) (string, error) {
	cmd := step.GetCommand()
	if cmd == "" {
		return "", nil // Nothing to execute
	}

	// Skip non-executable steps
	if !step.GetExecutable() {
		return fmt.Sprintf("Skipped (manual step): %s", cmd), nil
	}

	// Handle deputy internal commands
	if remediation.IsDeputyInternalCommand(cmd) {
		if err := remediation.ApplyDeputyCommand(workDir, cmd); err != nil {
			return "", err
		}
		return fmt.Sprintf("Applied: %s", cmd), nil
	}

	// Determine execution directory
	execDir := workDir
	if manifestPath := step.GetManifestPath(); manifestPath != "" {
		relDir := filepath.Dir(manifestPath)
		if relDir != "." && relDir != "" {
			execDir = filepath.Join(workDir, relDir)
		}
	}

	// Execute shell command
	args, err := remediation.ExecArgs(remediation.Command{
		Manager:    step.GetManager(),
		Command:    cmd,
		Executable: step.GetExecutable(),
	})
	if err != nil {
		return "", err
	}
	execCmd := exec.CommandContext(ctx, args[0], args[1:]...)
	execCmd.Dir = execDir

	output, err := execCmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// ExecuteWithAgent uses an AI agent plugin to generate and apply fixes interactively.
//
// SECURITY: This method uses AI agents that can execute shell commands and modify files.
// It is only available in local mode (in-process clients). Remote servers
// MUST NOT enable local mode, as this would allow arbitrary code execution.
func (h *RemediationHandler) ExecuteWithAgent(
	ctx context.Context,
	req *connect.Request[remediationv1.ExecuteWithAgentRequest],
	stream *connect.ServerStream[remediationv1.AgentEvent],
) error {
	// Security: ExecuteWithAgent is only allowed in local mode
	if !h.localMode {
		return connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("ExecuteWithAgent is not available on remote servers; use local CLI or daemon mode"))
	}

	// Validate request using protovalidate rules
	if err := validateRequest(req.Msg); err != nil {
		return err
	}

	agentName := req.Msg.GetAgent()
	logs.Info(ctx, "executing with agent", "agent", agentName)

	// Get the agent plugin handler from registry
	handler, err := h.registry.Get(agentName)
	if err != nil {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("agent not found: %s", agentName))
	}

	// Get handler info to check capabilities
	infoResp, err := handler.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get agent info: %w", err))
	}
	info := infoResp.Msg

	// Check if plugin supports agentic capabilities
	if caps := info.GetCapabilities(); caps == nil || !caps.GetAgentic() {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("agent %s does not support agentic execution", agentName))
	}

	// Build the execution request
	execReq := buildAgentExecuteRequest(req.Msg)

	// Create cancellable context
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Generate session ID
	sessionID := generateSessionID()

	// Register session for approval handling
	session := &agentSession{
		handler:    handler,
		cancelFunc: cancel,
		approvals:  make(chan *agentv1.ApproveRequest, 1),
	}
	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()
	defer func() {
		h.sessionsMu.Lock()
		delete(h.sessions, sessionID)
		h.sessionsMu.Unlock()
	}()

	// Send initial event
	if err := stream.Send(&remediationv1.AgentEvent{
		Phase:     remediationv1.AgentPhase_AGENT_PHASE_ANALYZING,
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	// Get the Executor interface for in-process execution
	executor := agent.AsExecutor(handler)
	if executor == nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("agent %s does not support in-process execution", agentName))
	}

	// Execute using the iterator interface and forward events to our stream
	for event, err := range executor.ExecuteIter(execCtx, execReq) {
		if err != nil {
			_ = stream.Send(&remediationv1.AgentEvent{
				Phase:     remediationv1.AgentPhase_AGENT_PHASE_FAILED,
				SessionId: sessionID,
				Timestamp: timestamppb.Now(),
				Details: &remediationv1.AgentEvent_Error{
					Error: &remediationv1.AgentErrorEvent{
						Message: err.Error(),
						IsFatal: true,
					},
				},
			})
			return connect.NewError(connect.CodeInternal, err)
		}

		remEvent := convertAgentEventToRemediationEvent(event, sessionID)
		if err := stream.Send(remEvent); err != nil {
			return err
		}

		// Handle approval required events
		if event.GetApprovalRequired() != nil {
			// Wait for approval via ApproveStep RPC
			select {
			case approval := <-session.approvals:
				if _, err := handler.Approve(execCtx, connect.NewRequest(approval)); err != nil {
					// Log but don't fail
					_ = err
				}
			case <-execCtx.Done():
				return execCtx.Err()
			}
		}
	}

	// Send completion event
	if err := stream.Send(&remediationv1.AgentEvent{
		Phase:     remediationv1.AgentPhase_AGENT_PHASE_COMPLETED,
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	logs.Info(ctx, "agent execution completed", "agent", agentName, "session_id", sessionID)

	return nil
}

// ResumeAgent resumes a previous agent execution session.
func (h *RemediationHandler) ResumeAgent(
	ctx context.Context,
	req *connect.Request[remediationv1.ResumeAgentRequest],
	stream *connect.ServerStream[remediationv1.AgentEvent],
) error {
	// Validate request using protovalidate rules
	if err := validateRequest(req.Msg); err != nil {
		return err
	}

	sessionID := req.Msg.GetSessionId()
	logs.Info(ctx, "resuming agent session", "session_id", sessionID)

	// Look up the session to get the handler
	h.sessionsMu.RLock()
	session, ok := h.sessions[sessionID]
	h.sessionsMu.RUnlock()

	if !ok {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("session %s not found or expired", sessionID))
	}

	handler := session.handler

	// Get handler info to check capabilities
	infoResp, err := handler.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get agent info: %w", err))
	}

	// Check if plugin supports session resumption
	if caps := infoResp.Msg.GetCapabilities(); caps == nil || !caps.GetSessionResumption() {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("agent does not support session resumption"))
	}

	// Get the Executor interface for in-process execution
	executor := agent.AsExecutor(handler)
	if executor == nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("agent does not support in-process execution"))
	}

	// Build resume request
	resumeReq := &agentv1.ResumeRequest{
		SessionId: sessionID,
		Prompt:    req.Msg.GetMessage(),
	}

	// Resume using the iterator interface and forward events to our stream
	for event, err := range executor.ResumeIter(ctx, resumeReq) {
		if err != nil {
			_ = stream.Send(&remediationv1.AgentEvent{
				Phase:     remediationv1.AgentPhase_AGENT_PHASE_FAILED,
				SessionId: sessionID,
				Timestamp: timestamppb.Now(),
				Details: &remediationv1.AgentEvent_Error{
					Error: &remediationv1.AgentErrorEvent{
						Message: err.Error(),
						IsFatal: true,
					},
				},
			})
			return connect.NewError(connect.CodeInternal, err)
		}

		remEvent := convertAgentEventToRemediationEvent(event, sessionID)
		if err := stream.Send(remEvent); err != nil {
			return err
		}
	}

	// Send completion event
	if err := stream.Send(&remediationv1.AgentEvent{
		Phase:     remediationv1.AgentPhase_AGENT_PHASE_COMPLETED,
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	return nil
}

// ListAgents returns available AI agents for remediation.
func (h *RemediationHandler) ListAgents(
	ctx context.Context,
	req *connect.Request[remediationv1.ListAgentsRequest],
) (*connect.Response[remediationv1.ListAgentsResponse], error) {
	logs.Debug(ctx, "listing available agents")

	entries := h.registry.Entries()
	agents := make([]*remediationv1.AgentInfo, 0, len(entries))

	for _, entry := range entries {
		// Get info from each handler
		infoResp, err := entry.Handler.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
		if err != nil {
			logs.Warn(ctx, "failed to get agent info", "agent", entry.Name, "error", err)
			continue
		}
		info := infoResp.Msg
		caps := info.GetCapabilities()

		agents = append(agents, &remediationv1.AgentInfo{
			Name:        info.GetName(),
			DisplayName: info.GetDisplayName(),
			Description: info.GetDescription(),
			Capabilities: &remediationv1.AgentCapabilities{
				Streaming:         caps.GetStreaming(),
				ToolUse:           caps.GetToolUse(),
				Agentic:           caps.GetAgentic(),
				SessionResumption: caps.GetSessionResumption(),
			},
			IsAvailable: true,
		})
	}

	return connect.NewResponse(&remediationv1.ListAgentsResponse{
		Agents: agents,
	}), nil
}

// ApproveStep approves or denies a pending remediation step.
func (h *RemediationHandler) ApproveStep(
	ctx context.Context,
	req *connect.Request[remediationv1.ApproveStepRequest],
) (*connect.Response[remediationv1.ApproveStepResponse], error) {
	// Validate request using protovalidate rules
	if err := validateRequest(req.Msg); err != nil {
		return nil, err
	}

	sessionID := req.Msg.GetSessionId()
	stepID := req.Msg.GetStepId()
	logs.Info(ctx, "processing step approval",
		"session_id", sessionID,
		"step_id", stepID,
		"approved", req.Msg.GetApproved(),
	)

	// Find the session
	h.sessionsMu.RLock()
	session, ok := h.sessions[sessionID]
	h.sessionsMu.RUnlock()

	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("session %s not found", sessionID))
	}

	// Send approval to the session
	approval := &agentv1.ApproveRequest{
		SessionId:   sessionID,
		OperationId: stepID,
		Approved:    req.Msg.GetApproved(),
		Feedback:    req.Msg.GetReason(),
	}

	select {
	case session.approvals <- approval:
		return connect.NewResponse(&remediationv1.ApproveStepResponse{
			Accepted: true,
		}), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return connect.NewResponse(&remediationv1.ApproveStepResponse{
			Accepted: false,
			Message:  "No pending approval for this session",
		}), nil
	}
}

// Helper functions

// generatePlanID creates a unique plan identifier.
func generatePlanID() string {
	return fmt.Sprintf("plan-%d", time.Now().UnixNano())
}

// generateSessionID creates a unique session identifier using cryptographically secure random bytes.
func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := crypto_rand.Read(b); err != nil {
		// Fallback to time-based only if crypto/rand fails (shouldn't happen)
		return fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("session-%s", hex.EncodeToString(b))
}

// buildAgentExecuteRequest constructs an agentv1.ExecuteRequest from the proto request.
func buildAgentExecuteRequest(req *remediationv1.ExecuteWithAgentRequest) *agentv1.ExecuteRequest {
	// Build prompt from scan results
	prompt := buildAgentPrompt(req)

	// Configure sandbox from options
	sandbox := agentv1.SandboxMode_SANDBOX_MODE_READ_ONLY
	if opts := req.GetOptions(); opts != nil {
		switch opts.GetSandbox() {
		case "read-only":
			sandbox = agentv1.SandboxMode_SANDBOX_MODE_READ_ONLY
		case "workspace-write":
			sandbox = agentv1.SandboxMode_SANDBOX_MODE_WORKSPACE_WRITE
		case "full-access":
			sandbox = agentv1.SandboxMode_SANDBOX_MODE_FULL_ACCESS
		}
	}

	execReq := &agentv1.ExecuteRequest{
		Prompt:  prompt,
		WorkDir: req.GetTargetPath(),
		Sandbox: sandbox,
	}

	// Add vulnerability context if available
	if scanResult := req.GetScanResult(); scanResult != nil {
		target := scanResult.GetTarget()
		execReq.Context = &agentv1.ExecutionContext{
			Target: target.GetDisplayPath(),
		}

		for _, f := range scanResult.GetFindings() {
			pkg := f.GetPackage()
			advisory := f.GetAdvisory()
			if pkg == nil || advisory == nil {
				continue
			}
			// Get severity string from the proto severity object
			severityStr := ""
			if sev := advisory.GetSeverity(); sev != nil {
				severityStr = sev.GetLevel().String()
			}
			execReq.Context.Vulnerabilities = append(execReq.Context.Vulnerabilities,
				&agentv1.VulnerabilityContext{
					Id:            advisory.GetId(),
					Package:       pkg.GetName(),
					Version:       pkg.GetVersion(),
					Severity:      severityStr,
					Summary:       advisory.GetSummary(),
					FixedVersions: advisory.GetFixedVersions(),
				})
		}
	}

	return execReq
}

// buildAgentPrompt constructs the prompt for the AI agent from the request.
func buildAgentPrompt(req *remediationv1.ExecuteWithAgentRequest) string {
	var sb strings.Builder

	sb.WriteString("Fix the following security vulnerabilities:\n\n")

	// Get findings from scan result if available
	if scanResult := req.GetScanResult(); scanResult != nil {
		for _, f := range scanResult.GetFindings() {
			pkg := f.GetPackage()
			advisory := f.GetAdvisory()
			if pkg == nil || advisory == nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("- %s in %s@%s", advisory.GetId(), pkg.GetName(), pkg.GetVersion()))
			if fixedVersions := advisory.GetFixedVersions(); len(fixedVersions) > 0 {
				sb.WriteString(fmt.Sprintf(" (fix available: %s)", fixedVersions[0]))
			}
			sb.WriteString("\n")
		}
	}

	if req.GetPrompt() != "" {
		sb.WriteString("\nAdditional instructions: ")
		sb.WriteString(req.GetPrompt())
		sb.WriteString("\n")
	}

	return sb.String()
}

// convertAgentEventToRemediationEvent converts an agentv1.ExecuteEvent to remediationv1.AgentEvent.
func convertAgentEventToRemediationEvent(event *agentv1.ExecuteEvent, sessionID string) *remediationv1.AgentEvent {
	remEvent := &remediationv1.AgentEvent{
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
	}

	// Map execution phase to agent phase
	switch event.GetPhase() {
	case agentv1.ExecutionPhase_EXECUTION_PHASE_INITIALIZING:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_ANALYZING
	case agentv1.ExecutionPhase_EXECUTION_PHASE_ANALYZING:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_ANALYZING
	case agentv1.ExecutionPhase_EXECUTION_PHASE_PLANNING:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_PLANNING
	case agentv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_EXECUTING
	case agentv1.ExecutionPhase_EXECUTION_PHASE_VERIFYING:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_VERIFYING
	case agentv1.ExecutionPhase_EXECUTION_PHASE_WAITING_APPROVAL:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_AWAITING_APPROVAL
	case agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_COMPLETED
	case agentv1.ExecutionPhase_EXECUTION_PHASE_FAILED:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_FAILED
	case agentv1.ExecutionPhase_EXECUTION_PHASE_CANCELLED:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_INTERRUPTED
	default:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_EXECUTING
	}

	// Map event details
	switch d := event.GetDetails().(type) {
	case *agentv1.ExecuteEvent_Text:
		remEvent.Details = &remediationv1.AgentEvent_Text{
			Text: &remediationv1.AgentTextEvent{
				Text:      d.Text.GetText(),
				IsPartial: true,
			},
		}
	case *agentv1.ExecuteEvent_Command:
		var exitCode *int32
		if d.Command.GetExitCode() != 0 {
			ec := d.Command.GetExitCode()
			exitCode = &ec
		}
		remEvent.Details = &remediationv1.AgentEvent_Command{
			Command: &remediationv1.AgentCommandEvent{
				Command:  d.Command.GetCommand(),
				Status:   d.Command.GetStatus().String(),
				ExitCode: exitCode,
				Output:   d.Command.GetStdout() + d.Command.GetStderr(),
			},
		}
	case *agentv1.ExecuteEvent_File:
		remEvent.Details = &remediationv1.AgentEvent_File{
			File: &remediationv1.AgentFileEvent{
				Path:   d.File.GetPath(),
				Action: d.File.GetAction().String(),
				Status: d.File.GetStatus().String(),
			},
		}
	case *agentv1.ExecuteEvent_Error:
		remEvent.Details = &remediationv1.AgentEvent_Error{
			Error: &remediationv1.AgentErrorEvent{
				Message: d.Error.GetMessage(),
				IsFatal: d.Error.GetIsFatal(),
			},
		}
	case *agentv1.ExecuteEvent_Done:
		remEvent.Details = &remediationv1.AgentEvent_Summary{
			Summary: &remediationv1.AgentSummaryEvent{
				SessionId: d.Done.GetSessionId(),
				Success:   d.Done.GetReason() == agentv1.DoneReason_DONE_REASON_SUCCESS,
			},
		}
		if usage := d.Done.GetUsage(); usage != nil {
			remEvent.Details = &remediationv1.AgentEvent_Tokens{
				Tokens: &remediationv1.AgentTokensEvent{
					PromptTokens:     usage.GetPromptTokens(),
					CompletionTokens: usage.GetCompletionTokens(),
					TotalTokens:      usage.GetTotalTokens(),
				},
			}
		}
	case *agentv1.ExecuteEvent_Status:
		remEvent.Details = &remediationv1.AgentEvent_Status{
			Status: &remediationv1.AgentStatusEvent{
				Status: d.Status.GetStatus(),
			},
		}
	case *agentv1.ExecuteEvent_ApprovalRequired:
		remEvent.Phase = remediationv1.AgentPhase_AGENT_PHASE_AWAITING_APPROVAL
		riskLevel := remediationv1.RiskLevel_RISK_LEVEL_MEDIUM
		if d.ApprovalRequired.GetIsHighRisk() {
			riskLevel = remediationv1.RiskLevel_RISK_LEVEL_HIGH
		}
		remEvent.Details = &remediationv1.AgentEvent_Approval{
			Approval: &remediationv1.AgentApprovalEvent{
				RequestId:      d.ApprovalRequired.GetOperationId(),
				OperationType:  d.ApprovalRequired.GetOperationType().String(),
				Description:    d.ApprovalRequired.GetDescription(),
				RiskLevel:      riskLevel,
				TimeoutSeconds: d.ApprovalRequired.GetTimeoutSeconds(),
			},
		}
	}

	return remEvent
}
