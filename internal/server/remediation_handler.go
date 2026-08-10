package server

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	// execStep runs a single remediation step. It defaults to executeStep and
	// exists as a seam so tests can observe or suppress command execution
	// without spawning real processes.
	execStep func(ctx context.Context, workDir string, step *remediationv1.Step) (string, error)
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
		execStep: executeStep,
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
	if err := validateRequest(req.Msg); err != nil {
		return nil, err
	}

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
			Target:      scanResult.GetTarget(),
			GeneratedAt: timestamppb.Now(),
			Stats:       &remediationv1.PlanStats{},
		}), nil
	}

	logs.Info(ctx, "generating remediation plan", "findings", len(findings))

	// Consolidate findings the same way scan surfaces do: alias dedup, fix
	// verdict resolution, and severity normalization. Planning from raw
	// findings would lose migration targets and duplicate aliased advisories.
	internalScan := internalproto.ScanningResultFromProto(scanResult)
	consolidated := vulnerability.ConsolidateAll(internalScan.Findings, internalScan.Advisories)

	// Generate remediation commands with hints adapted to the caller surface.
	commands, stdlibVersion := remediation.CommandsFromConsolidated(consolidated.Vulnerabilities)
	commands = remediation.ApplyGuidance(commands, guidanceContextFor(req.Msg.GetOptions().GetGuidanceProfile()))

	// Identify findings the plan actually addresses: a finding counts only
	// when at least one generated command carries its ID. A finding can be
	// remediable in principle yet produce no command (for example when every
	// declaring manifest is a vendored install-tree copy), and counting it as
	// addressed would let a consumer mark it resolved after zero steps.
	coveredByPlan := make(map[string]struct{})
	for _, cmd := range commands {
		for _, id := range cmd.Vulnerabilities {
			coveredByPlan[id] = struct{}{}
		}
	}
	addressed := 0
	var unaddressed []string
	for _, v := range consolidated.Vulnerabilities {
		if _, ok := coveredByPlan[v.PrimaryID]; ok {
			addressed++
		} else {
			unaddressed = append(unaddressed, v.PrimaryID)
		}
	}

	// Convert to proto steps
	steps := internalproto.RemediationCommandsToSteps(commands)

	// Build the plan
	plan := &remediationv1.Plan{
		Id:            generatePlanID(),
		Steps:         steps,
		Target:        scanResult.GetTarget(),
		StdlibUpgrade: stdlibVersion,
		GeneratedAt:   timestamppb.Now(),
	}

	// Build response
	response := &remediationv1.GeneratePlanResponse{
		Plan:                       plan,
		Target:                     scanResult.GetTarget(),
		GeneratedAt:                timestamppb.Now(),
		Stats:                      planStats(steps, addressed, len(unaddressed)),
		UnaddressedVulnerabilities: unaddressed,
	}

	logs.Info(ctx, "remediation plan generated",
		"plan_id", plan.Id,
		"steps", len(steps),
		"addressed", addressed,
		"unaddressed", len(unaddressed),
	)

	return connect.NewResponse(response), nil
}

// guidanceContextFor maps the requested guidance profile onto the internal
// guidance context. Unspecified keeps the API profile, the handler's
// historical default.
func guidanceContextFor(profile remediationv1.GuidanceProfile) remediation.GuidanceContext {
	switch profile {
	case remediationv1.GuidanceProfile_GUIDANCE_PROFILE_CLI:
		return remediation.CLIGuidance()
	case remediationv1.GuidanceProfile_GUIDANCE_PROFILE_MCP:
		return remediation.MCPGuidance()
	case remediationv1.GuidanceProfile_GUIDANCE_PROFILE_GENERIC:
		return remediation.GuidanceContext{Profile: remediation.GuidanceProfileGeneric}
	default:
		return remediation.APIGuidance()
	}
}

// planStats summarizes a plan's steps together with the finding disposition
// counts computed during planning.
func planStats(steps []*remediationv1.Step, addressed, unaddressed int) *remediationv1.PlanStats {
	stats := &remediationv1.PlanStats{
		TotalSteps:                 int32(len(steps)),
		VulnerabilitiesAddressed:   int32(addressed),
		VulnerabilitiesUnaddressed: int32(unaddressed),
	}
	packages := make(map[string]struct{})
	managers := make(map[string]struct{})
	for _, step := range steps {
		if step.GetExecutable() {
			stats.ExecutableSteps++
		} else {
			stats.ManualSteps++
		}
		if step.GetMigration() {
			stats.MigrationSteps++
		}
		if step.GetRiskLevel() >= remediationv1.RiskLevel_RISK_LEVEL_HIGH {
			stats.HighRiskSteps++
		}
		if name := step.GetPackageName(); name != "" {
			packages[name] = struct{}{}
		}
		if manager := step.GetManager(); manager != "" {
			managers[manager] = struct{}{}
		}
	}
	stats.AffectedPackages = int32(len(packages))
	stats.AffectedManagers = slices.Sorted(maps.Keys(managers))
	return stats
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

	// Fail closed on execution options the handler cannot honor: silently
	// ignoring a requested safety control and executing anyway is worse than
	// refusing outright.
	opts := req.Msg.GetOptions()
	if err := rejectUnsupportedApprovalMode(opts.GetApprovalMode()); err != nil {
		return err
	}
	dryRun := opts.GetDryRun()
	// StopOnError promises "halts execution if any step fails"
	// (deputy.remediation.v1.ExecutionOptions); when unset, execution
	// continues past failed steps and reports them through per-step FAILED
	// events and the terminal phase.
	stopOnError := opts.GetStopOnError()
	// VerboseOutput promises "includes full command output instead of
	// summaries"; when unset, completion events carry a one-line summary.
	verbose := opts.GetVerboseOutput()
	skipSteps := make(map[string]struct{}, len(opts.GetSkipStepIds()))
	for _, id := range opts.GetSkipStepIds() {
		skipSteps[id] = struct{}{}
	}
	// A malformed or negative timeout is a broken safety limit, not "no
	// timeout": silently executing without a deadline would disable a
	// control the client asked for. Zero or absent keeps meaning no timeout.
	if timeoutpb := opts.GetTimeout(); timeoutpb != nil {
		if err := timeoutpb.CheckValid(); err != nil {
			return connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("options.timeout is invalid: %w", err))
		}
	}
	timeout := opts.GetTimeout().AsDuration()
	if timeout < 0 {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("options.timeout must not be negative, got %s", timeout))
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Dependency references are part of the plan's shape, so validate them
	// up front rather than discovering an impossible ordering mid-run.
	if err := validateStepDependencies(plan.GetSteps()); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
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
		"dry_run", dryRun,
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
		// The zero-step branch must not bypass the timeout: an expired
		// context cannot be reported as a completed plan.
		if err := ctx.Err(); err != nil {
			return connect.NewError(stepFailureCode(ctx, err),
				fmt.Errorf("plan execution stopped before completion: %w", err))
		}
		// No steps to execute
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
			Message:   "No steps to execute",
			Progress:  100,
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
		return nil
	}

	// Execute each step
	runStep := h.execStep
	if runStep == nil {
		// Zero-value handlers (constructed without NewRemediationHandler)
		// still execute real steps rather than panicking.
		runStep = executeStep
	}
	executed := 0
	skipped := 0
	failed := 0
	wouldExecute := 0
	wouldReject := 0
	// satisfied holds the steps that actually succeeded, which is what a
	// dependent step's prerequisites are checked against. A skipped or failed
	// step never lands here, so its dependents are skipped in turn.
	satisfied := make(map[string]struct{}, len(steps))
	for i, step := range steps {
		// executeStep is the only branch that observes the context on its
		// own; skip and dry-run steps would otherwise sail past an expired
		// timeout, so enforce it here before every step regardless of branch.
		if err := ctx.Err(); err != nil {
			return connect.NewError(stepFailureCode(ctx, err),
				fmt.Errorf("plan execution stopped before step %d/%d: %w", i+1, len(steps), err))
		}

		stepID := effectiveStepID(step, i)

		// A step whose prerequisites did not succeed must not run: applying
		// a follow-up mutation without its setup is worse than not applying
		// it. This precedes the skip list only in the sense that both are
		// checked before execution; an explicitly skipped step is reported
		// as such below.
		if _, skip := skipSteps[stepID]; !skip {
			if dep, unmet := unmetDependency(step, satisfied); unmet {
				skipped++
				if err := stream.Send(&remediationv1.ExecutionEvent{
					Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
					StepId:    stepID,
					Message:   fmt.Sprintf("Skipped step %d/%d (unmet dependency %s): %s", i+1, len(steps), dep, stepLabel(step)),
					Progress:  executionProgress(i+1, len(steps)),
					Timestamp: timestamppb.Now(),
				}); err != nil {
					return err
				}
				continue
			}
		}

		// Honor the skip list before anything about the step runs.
		if _, skip := skipSteps[stepID]; skip {
			skipped++
			if err := stream.Send(&remediationv1.ExecutionEvent{
				Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
				StepId:    stepID,
				Message:   fmt.Sprintf("Skipped step %d/%d (requested via skip_step_ids): %s", i+1, len(steps), step.GetTitle()),
				Progress:  executionProgress(i+1, len(steps)),
				Timestamp: timestamppb.Now(),
			}); err != nil {
				return err
			}
			continue
		}

		// Dry run: describe what would run without ever reaching command
		// execution. This branch must stay ahead of the execStep call so the
		// simulation can never execute anything. Only executable steps with
		// commands count toward the would-execute total; manual and
		// commandless steps are described but never run.
		if dryRun {
			message, outcome := dryRunStep(i+1, len(steps), step)
			phase := remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING
			switch outcome {
			case dryRunWouldRun:
				wouldExecute++
				// A step that would run counts as satisfied for the steps
				// that depend on it, so the simulation predicts the same
				// ordering a real run would take.
				satisfied[stepID] = struct{}{}
			case dryRunWouldReject:
				// A step a real run would refuse is a prediction of failure,
				// so report it as one and leave its dependents unsatisfied.
				wouldReject++
				phase = remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED
			}
			if err := stream.Send(&remediationv1.ExecutionEvent{
				Phase:     phase,
				StepId:    stepID,
				Message:   message,
				Progress:  executionProgress(i+1, len(steps)),
				Timestamp: timestamppb.Now(),
			}); err != nil {
				return err
			}
			continue
		}

		// Steps that cannot be run (manual guidance, or no command at all)
		// are skipped, never executed. Their status is reported here rather
		// than inferred from execution output, so a plan can never report a
		// manual step as completed work.
		if reason, runnable := stepSkipReason(step); !runnable {
			skipped++
			if err := stream.Send(&remediationv1.ExecutionEvent{
				Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
				StepId:    stepID,
				Message:   fmt.Sprintf("Skipped step %d/%d (%s): %s", i+1, len(steps), reason, stepLabel(step)),
				Progress:  executionProgress(i+1, len(steps)),
				Timestamp: timestamppb.Now(),
			}); err != nil {
				return err
			}
			continue
		}

		// Send step starting event
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
			StepId:    stepID,
			Message:   fmt.Sprintf("Executing step %d/%d: %s", i+1, len(steps), step.GetTitle()),
			Progress:  executionProgress(i, len(steps)),
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}

		// Execute the step
		output, execErr := runStep(ctx, absWorkDir, step)

		if execErr != nil {
			failed++
			// Failure events carry command output regardless of the
			// verbosity setting: diagnostics for a failed step must not
			// depend on a summarization flag.
			failMsg := fmt.Sprintf("Step failed: %v", execErr)
			if output != "" {
				failMsg = fmt.Sprintf("Step failed: %v\n%s", execErr, output)
			}
			if err := stream.Send(&remediationv1.ExecutionEvent{
				Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
				StepId:    stepID,
				Message:   failMsg,
				Progress:  executionProgress(i+1, len(steps)),
				Timestamp: timestamppb.Now(),
			}); err != nil {
				return err
			}
			if stopOnError {
				// Halt as the option promises; the terminal error carries
				// the cause-appropriate code.
				return connect.NewError(stepFailureCode(ctx, execErr), fmt.Errorf("step %s failed: %w", stepID, execErr))
			}
			continue
		}
		executed++
		satisfied[stepID] = struct{}{}

		// Send step completed event: a one-line summary by default, with the
		// full command output only when verbose_output is set.
		completeMsg := fmt.Sprintf("Completed step %d/%d: %s", i+1, len(steps), stepLabel(step))
		if verbose && output != "" {
			completeMsg = fmt.Sprintf("%s\n%s", completeMsg, output)
		}
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_EXECUTING,
			StepId:    stepID,
			Message:   completeMsg,
			Progress:  executionProgress(i+1, len(steps)),
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
	}

	// A plan must not report success under an expired or cancelled context,
	// even when every step branch already ran (for example all steps skipped).
	if err := ctx.Err(); err != nil {
		return connect.NewError(stepFailureCode(ctx, err),
			fmt.Errorf("plan execution stopped before completion: %w", err))
	}

	// A dry run reports what it predicted. Predicted rejections make the run
	// a failed prediction, not a clean one: reporting COMPLETED would tell a
	// client the plan is safe to apply when part of it would be refused.
	if dryRun {
		dryMsg := fmt.Sprintf("Dry run complete: %d steps would execute", wouldExecute)
		if wouldReject > 0 {
			dryMsg = fmt.Sprintf("%s, %d would be rejected", dryMsg, wouldReject)
		}
		dryMsg += ", nothing was changed"
		if skipped > 0 {
			dryMsg = fmt.Sprintf("%s (%d skipped)", dryMsg, skipped)
		}
		dryPhase := remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED
		if wouldReject > 0 {
			dryPhase = remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED
		}
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     dryPhase,
			Message:   dryMsg,
			Progress:  100,
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
		logs.Info(ctx, "remediation plan dry run complete",
			"plan_id", plan.GetId(),
			"steps_would_execute", wouldExecute,
			"steps_would_reject", wouldReject,
			"steps_skipped", skipped,
		)
		return nil
	}

	// A run that continued past failures (stop_on_error unset) ends with a
	// terminal FAILED phase carrying the honest counts: the plan ran to the
	// end as requested but did not fully succeed. The stream itself returns
	// nil because the RPC did exactly what was asked; per-step FAILED events
	// already carried the diagnostics.
	if failed > 0 {
		partialMsg := fmt.Sprintf("Executed %d steps: %d succeeded, %d failed", executed+failed, executed, failed)
		if skipped > 0 {
			partialMsg = fmt.Sprintf("%s (%d skipped)", partialMsg, skipped)
		}
		if err := stream.Send(&remediationv1.ExecutionEvent{
			Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
			Message:   partialMsg,
			Progress:  100,
			Timestamp: timestamppb.Now(),
		}); err != nil {
			return err
		}
		logs.Info(ctx, "remediation plan executed with failures",
			"plan_id", plan.GetId(),
			"steps_executed", executed,
			"steps_failed", failed,
			"steps_skipped", skipped,
		)
		return nil
	}

	// Send completion event
	completionMsg := fmt.Sprintf("Successfully executed %d steps", executed)
	if skipped > 0 {
		completionMsg = fmt.Sprintf("%s (%d skipped)", completionMsg, skipped)
	}
	if err := stream.Send(&remediationv1.ExecutionEvent{
		Phase:     remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Message:   completionMsg,
		Progress:  100,
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	logs.Info(ctx, "remediation plan executed successfully",
		"plan_id", plan.GetId(),
		"steps_executed", executed,
		"steps_skipped", skipped,
	)

	return nil
}

// stepFailureCode maps a step execution error onto the connect code clients
// need to distinguish causes: a step stopped by the client-configured timeout
// or a cancelled call must not masquerade as a server-side internal failure.
// The context is consulted first because a command killed mid-run surfaces as
// an exec exit error (signal: killed) that does not wrap the context
// sentinel; when the context is still live, the sentinels arrive wrapped, so
// match with errors.Is.
func stepFailureCode(ctx context.Context, err error) connect.Code {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return connect.CodeDeadlineExceeded
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	case errors.Is(err, errProcessTreeUnbounded):
		return connect.CodeUnimplemented
	default:
		return connect.CodeInternal
	}
}

// rejectUnsupportedApprovalMode fails closed on approval modes ExecutePlan
// cannot honor. The handler has no interactive approval loop for plan
// execution (that exists only for ExecuteWithAgent), so accepting
// INTERACTIVE, ALL_STEPS, or SKIP_HIGH_RISK and then executing every step
// unconditionally would silently discard a requested safety control. Only
// UNSPECIFIED and AUTO_APPROVE match what the handler actually does.
func rejectUnsupportedApprovalMode(mode remediationv1.ApprovalMode) error {
	switch mode {
	case remediationv1.ApprovalMode_APPROVAL_MODE_UNSPECIFIED,
		remediationv1.ApprovalMode_APPROVAL_MODE_AUTO_APPROVE:
		return nil
	default:
		return connect.NewError(connect.CodeUnimplemented, fmt.Errorf(
			"approval mode %s is not supported by ExecutePlan; supported modes: %s, %s",
			mode,
			remediationv1.ApprovalMode_APPROVAL_MODE_UNSPECIFIED,
			remediationv1.ApprovalMode_APPROVAL_MODE_AUTO_APPROVE,
		))
	}
}

// effectiveStepID returns the ID a step is addressed by, falling back to its
// position when the plan left the ID empty. Dependency references and the
// skip list are matched against this value, so it must be derived the same
// way everywhere.
func effectiveStepID(step *remediationv1.Step, index int) string {
	if id := step.GetId(); id != "" {
		return id
	}
	return fmt.Sprintf("step-%d", index+1)
}

// validateStepDependencies rejects plans whose depends_on references cannot
// be honored by in-order execution. Steps run in plan order, so a dependency
// must name an earlier step: an unknown ID can never be satisfied, and a self
// or forward reference asks for an ordering the plan itself contradicts.
// Requiring earlier-only references also rules out dependency cycles, since a
// cycle needs at least one backward edge.
func validateStepDependencies(steps []*remediationv1.Step) error {
	seen := make(map[string]struct{}, len(steps))
	known := make(map[string]struct{}, len(steps))
	for i, step := range steps {
		known[effectiveStepID(step, i)] = struct{}{}
	}

	for i, step := range steps {
		stepID := effectiveStepID(step, i)
		for _, dep := range step.GetDependsOn() {
			if _, ok := known[dep]; !ok {
				return fmt.Errorf("step %q depends on unknown step %q", stepID, dep)
			}
			if _, ok := seen[dep]; !ok {
				return fmt.Errorf("step %q depends on step %q, which does not run before it", stepID, dep)
			}
		}
		seen[stepID] = struct{}{}
	}
	return nil
}

// unmetDependency returns the first prerequisite of a step that did not
// succeed, so the step can be skipped rather than applying a follow-up
// mutation whose setup never happened.
func unmetDependency(step *remediationv1.Step, satisfied map[string]struct{}) (string, bool) {
	for _, dep := range step.GetDependsOn() {
		if _, ok := satisfied[dep]; !ok {
			return dep, true
		}
	}
	return "", false
}

// stepSkipReason reports whether a step can actually be run, and if not, the
// short reason to surface to the client. Plans legitimately carry steps that
// describe work a human must do (module migrations) or that carry no command
// at all; running is not possible for either, and reporting them as executed
// would tell a client a vulnerability was remediated when nothing happened.
func stepSkipReason(step *remediationv1.Step) (reason string, runnable bool) {
	switch {
	case step.GetCommand() == "":
		return "no command", false
	case !step.GetExecutable():
		return "manual step", false
	default:
		return "", true
	}
}

// stepLabel identifies a step in human-readable event messages, preferring
// the concrete command over the title so summaries still say what ran.
func stepLabel(step *remediationv1.Step) string {
	if cmd := step.GetCommand(); cmd != "" {
		return cmd
	}
	return step.GetTitle()
}

// dryRunOutcome is what a dry run predicts for a single step.
type dryRunOutcome int

const (
	// dryRunWouldRun means the step passed preflight and a real run would
	// carry it out.
	dryRunWouldRun dryRunOutcome = iota
	// dryRunNotRunnable means the step is not executable work (manual
	// guidance, or no command), so a real run would skip it.
	dryRunNotRunnable
	// dryRunWouldReject means a real run would refuse the step before
	// executing anything, for example a command that is not permitted for
	// its manager.
	dryRunWouldReject
)

// dryRunStep predicts what a real run would do with a step and describes it,
// without executing or mutating anything. Prediction is the entire point of a
// dry run, so it performs the same non-mutating validation the real path does
// (command parsing and the manager executable allowlist, via
// remediation.ExecArgs). Without that, a step whose manager and command
// disagree would be reported as runnable and then fail for real.
//
// Deputy-internal commands are validated only for parseability: they are
// applied in process rather than executed, so ExecArgs does not apply to
// them, and their argument-level checks live in the apply path.
func dryRunStep(position, total int, step *remediationv1.Step) (string, dryRunOutcome) {
	cmd := step.GetCommand()
	switch {
	case cmd == "":
		return fmt.Sprintf("[dry run] Step %d/%d has no command: %s", position, total, step.GetTitle()), dryRunNotRunnable
	case !step.GetExecutable():
		return fmt.Sprintf("[dry run] Step %d/%d is manual: %s", position, total, cmd), dryRunNotRunnable
	}

	if remediation.IsDeputyInternalCommand(cmd) {
		if _, err := remediation.ValidateDeputyCommand(cmd); err != nil {
			return fmt.Sprintf("[dry run] Step %d/%d would be rejected: %s (%v)", position, total, cmd, err), dryRunWouldReject
		}
		return fmt.Sprintf("[dry run] Step %d/%d would apply: %s", position, total, cmd), dryRunWouldRun
	}

	if _, err := remediation.ExecArgs(remediation.Command{
		Manager:    step.GetManager(),
		Command:    cmd,
		Executable: step.GetExecutable(),
	}); err != nil {
		return fmt.Sprintf("[dry run] Step %d/%d would be rejected: %s (%v)", position, total, cmd, err), dryRunWouldReject
	}

	return fmt.Sprintf("[dry run] Step %d/%d would execute: %s", position, total, cmd), dryRunWouldRun
}

// executionProgress converts a completed-step count into the 0-100 completion
// percentage the ExecutionEvent contract declares for its progress field.
func executionProgress(done, total int) int32 {
	if total <= 0 {
		return 0
	}
	return int32(done * 100 / total)
}

// errProcessTreeUnbounded marks a refusal to spawn an external command on a
// platform where cancellation cannot terminate the command's descendants.
// It is a capability gap in the build, not a runtime fault, so it maps to
// CodeUnimplemented.
var errProcessTreeUnbounded = errors.New("this platform cannot terminate a command's child processes, so an execution timeout could not bound them")

// commandWaitDelay bounds how long a cancelled command may keep the RPC
// waiting on its output pipes after its process group has been killed. It is
// a backstop for a descendant that escaped the group, not the primary
// mechanism, so it is short.
const commandWaitDelay = 5 * time.Second

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
	// Both execution paths must respect cancellation: exec.CommandContext
	// does on its own, but deputy-internal commands apply file edits without
	// a context, so an expired timeout must stop the step before it starts.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("step not started: %w", err)
	}

	cmd := step.GetCommand()
	if cmd == "" {
		return "", nil // Nothing to execute
	}

	// Non-executable steps are not runnable work. ExecutePlan classifies and
	// reports them before reaching here (see stepSkipReason), so this guard
	// only protects direct callers; it must never be treated as success by a
	// caller counting executed steps.
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

	// Determine execution directory. The manifest path is plan data, so
	// confine the resolved directory to the work directory: a crafted
	// ../ path must not steer command execution outside it.
	execDir := workDir
	if manifestPath := step.GetManifestPath(); manifestPath != "" {
		relDir := filepath.Dir(manifestPath)
		if relDir != "." && relDir != "" {
			candidate := filepath.Join(workDir, relDir)
			rel, err := filepath.Rel(workDir, candidate)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("manifest path %q escapes the work directory", manifestPath)
			}
			execDir = candidate
		}
	}

	// Fail closed where the timeout cannot bound the process tree. Running
	// anyway would mean descendants keep mutating the workspace after the
	// deadline, so refuse instead of offering a silently weaker guarantee on
	// one platform. Deputy-internal commands are handled above and stay
	// available, since they never spawn a process.
	if !processTreeTerminationSupported {
		return "", fmt.Errorf("refusing to run %q: %w", cmd, errProcessTreeUnbounded)
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

	// Bound the whole process tree by the context, not just the direct child:
	// remediation commands routinely fork (a package manager driving a
	// compiler), and a surviving descendant would keep modifying the
	// workspace after the caller's timeout expired.
	configureProcessGroup(execCmd)
	execCmd.Cancel = func() error { return terminateProcessGroup(execCmd) }
	// Backstop for a descendant that somehow escapes the group kill and holds
	// the output pipes open: stop waiting on its I/O shortly after the kill
	// rather than blocking the RPC for the descendant's full lifetime.
	execCmd.WaitDelay = commandWaitDelay

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

		for _, remEvent := range convertAgentEventToRemediationEvents(event, sessionID) {
			if err := stream.Send(remEvent); err != nil {
				return err
			}
		}

		// Handle approval required events
		if event.GetApprovalRequired() != nil {
			// Wait for approval via ApproveStep RPC
			select {
			case approval := <-session.approvals:
				if _, err := handler.Approve(execCtx, connect.NewRequest(approval)); err != nil {
					// The agent keeps running; surface the undelivered
					// approval instead of failing the stream.
					logs.Warn(execCtx, "agent approval delivery failed", "error", err)
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

		for _, remEvent := range convertAgentEventToRemediationEvents(event, sessionID) {
			if err := stream.Send(remEvent); err != nil {
				return err
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

		// Execution requires everything ExecuteWithAgent checks before
		// running: local mode (remote servers refuse agent execution
		// outright), the agentic flag, and in-process executor support.
		executes := h.localMode && caps.GetAgentic() && agent.AsExecutor(entry.Handler) != nil
		approvals := executes && caps.GetApprovalWorkflows()

		agents = append(agents, &remediationv1.AgentInfo{
			Name:         info.GetName(),
			DisplayName:  info.GetDisplayName(),
			Description:  info.GetDescription(),
			Capabilities: remediationAgentCapabilities(caps, executes, approvals),
			// Availability reflects registry presence; what the agent may do
			// through this handler is expressed by the capability flags.
			IsAvailable: true,
		})
	}

	return connect.NewResponse(&remediationv1.ListAgentsResponse{
		Agents: agents,
	}), nil
}

// remediationAgentCapabilities maps the agent plugin capability contract onto
// the remediation API's capability fields so ListAgents advertises what an
// agent can actually do through this handler. The plugin contract does not
// model code execution, file modification, or approval workflows as separate
// flags, so the caller supplies them: executes reports whether
// ExecuteWithAgent could actually run the agent (local mode, agentic flag,
// in-process agent.Executor support), and drives code_execution and
// file_modification because agentic means autonomous code execution.
// approvals additionally requires the agent to report approval_workflows in
// its own capabilities: every plugin structurally has an Approve method, so
// only that declaration distinguishes real approval delivery from the
// Unimplemented stub that ExecuteWithAgent's handoff would silently drop.
// It travels in the plugin's GetInfo response, so it reaches this handler
// identically whether the agent is in-process, pluginrpc, or ConnectRPC.
func remediationAgentCapabilities(caps *agentv1.AgentCapabilities, executes, approvals bool) *remediationv1.AgentCapabilities {
	return &remediationv1.AgentCapabilities{
		Streaming:         caps.GetStreaming(),
		ToolUse:           caps.GetToolUse(),
		Agentic:           caps.GetAgentic(),
		SessionResumption: caps.GetSessionResumption(),
		CodeExecution:     executes,
		FileModification:  executes,
		ApprovalWorkflows: approvals,
	}
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
		// CanProceed reports whether the step may continue: a delivered
		// denial is still accepted, but the denied step must not proceed.
		return connect.NewResponse(&remediationv1.ApproveStepResponse{
			Accepted:   true,
			CanProceed: req.Msg.GetApproved(),
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

// generatePlanID creates a unique plan identifier. It uses random bytes so
// concurrent plans can never collide; the time-based form only remains as a
// fallback if crypto/rand fails.
func generatePlanID() string {
	b := make([]byte, 8)
	if _, err := crypto_rand.Read(b); err != nil {
		return fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	return "plan-" + hex.EncodeToString(b)
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

// convertAgentEventToRemediationEvents converts an agentv1.ExecuteEvent into
// the remediationv1.AgentEvents to stream, in send order. Most upstream
// events map one-to-one, but a remediation event carries a single details
// payload, so a Done event that also reports token usage expands into two
// events: the tokens event first (with a nonterminal phase), then the
// terminal summary, so the summary is both the first terminal event and the
// last detail a client sees for the session.
func convertAgentEventToRemediationEvents(event *agentv1.ExecuteEvent, sessionID string) []*remediationv1.AgentEvent {
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
		// Token usage is additional detail on the same Done event; emit it as
		// its own event ahead of the summary rather than replacing the
		// summary, which is the terminal signal clients rely on.
		if usage := d.Done.GetUsage(); usage != nil {
			tokensEvent := &remediationv1.AgentEvent{
				SessionId: sessionID,
				Timestamp: remEvent.GetTimestamp(),
				// A nonterminal phase: consumers detect stream completion
				// through terminal phases (IsAgentTerminal), so the summary
				// must be the first terminal event they see.
				Phase: remediationv1.AgentPhase_AGENT_PHASE_EXECUTING,
				Details: &remediationv1.AgentEvent_Tokens{
					Tokens: &remediationv1.AgentTokensEvent{
						PromptTokens:     usage.GetPromptTokens(),
						CompletionTokens: usage.GetCompletionTokens(),
						TotalTokens:      usage.GetTotalTokens(),
					},
				},
			}
			return []*remediationv1.AgentEvent{tokensEvent, remEvent}
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

	return []*remediationv1.AgentEvent{remEvent}
}
