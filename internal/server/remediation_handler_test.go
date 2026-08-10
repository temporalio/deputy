package server

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
	"github.com/temporalio/deputy/gen/deputy/remediation/v1/remediationv1connect"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/agent"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// TestGeneratePlanAcceptsEcosystemlessPackages pins a live-spin regression:
// scan results legitimately contain packages without a package ecosystem
// (Dockerfile base-image references, unrecognized SBOM components), and plan
// generation must not reject the whole scan over them.
func TestGeneratePlanAcceptsEcosystemlessPackages(t *testing.T) {
	vulnerable := &dependencyv1.Package{
		Name:      "github.com/example/widget",
		Version:   "v1.4.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/widget@v1.4.0",
		Direct:    true,
		ManifestRefs: []*dependencyv1.ManifestRef{
			{Path: "go.mod", Manager: "go"},
		},
	}
	baseImage := &dependencyv1.Package{
		Name:    "library/golang",
		Version: "1.24",
		Purl:    "pkg:docker/library%2Fgolang@1.24",
		Direct:  true,
	}

	scan := &scanv1.ScanResponse{
		PackagesScanned: 2,
		Packages:        []*dependencyv1.Package{vulnerable, baseImage},
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "GO-2026-0001", Package: vulnerable, Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2026-0001": {
				Id:            "GO-2026-0001",
				Summary:       "Fixable vulnerability",
				Severity:      vulnerability.NewSeverity("HIGH", ""),
				FixedVersions: []string{"1.5.0"},
			},
		},
		Stats: &vulnerabilityv1.Stats{Total: 1, Unique: 1, High: 1},
	}

	handler := NewRemediationHandler()
	resp, err := handler.GeneratePlan(t.Context(), connect.NewRequest(&remediationv1.GeneratePlanRequest{
		Source: &remediationv1.GeneratePlanRequest_ScanResult{ScanResult: scan},
	}))
	if err != nil {
		t.Fatalf("GeneratePlan rejected a scan with an ecosystem-less package: %v", err)
	}
	if got := resp.Msg.GetStats().GetVulnerabilitiesAddressed(); got != 1 {
		t.Fatalf("vulnerabilitiesAddressed = %d, want 1", got)
	}
	var covered bool
	for _, step := range resp.Msg.GetPlan().GetSteps() {
		for _, id := range step.GetAffectedVulnerabilities() {
			if id == "GO-2026-0001" {
				covered = true
			}
		}
	}
	if !covered {
		t.Fatalf("no step remediates GO-2026-0001: %+v", resp.Msg.GetPlan().GetSteps())
	}
}

// stepRecorder substitutes the handler's execStep seam so tests can assert
// exactly which steps reached command execution without spawning processes.
type stepRecorder struct {
	mu          sync.Mutex
	stepIDs     []string
	hadDeadline bool
	failSteps   []string // step IDs whose execution is reported as failed
}

// run records the step and whether the execution context carried a deadline,
// standing in for real command execution. Steps listed in failSteps fail
// with output, mimicking a command that produced diagnostics and exited
// nonzero.
func (r *stepRecorder) run(ctx context.Context, _ string, step *remediationv1.Step) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, r.hadDeadline = ctx.Deadline()
	r.stepIDs = append(r.stepIDs, step.GetId())
	if slices.Contains(r.failSteps, step.GetId()) {
		return "failure output", errors.New("simulated step failure")
	}
	return "recorded output", nil
}

// executedSteps returns the IDs of steps that reached execution.
func (r *stepRecorder) executedSteps() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.stepIDs)
}

// newRemediationTestClient serves the handler over an in-process HTTP server
// and returns a ConnectRPC client, the harness for streaming RPC tests.
func newRemediationTestClient(t *testing.T, h *RemediationHandler) remediationv1connect.RemediationServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(remediationv1connect.NewRemediationServiceHandler(h))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return remediationv1connect.NewRemediationServiceClient(ts.Client(), ts.URL)
}

// executePlanForTest runs ExecutePlan with the given options against a
// two-step plan (plus any extra steps) and returns the streamed events and
// the terminal error.
func executePlanForTest(t *testing.T, rec *stepRecorder, options *remediationv1.ExecutionOptions, extraSteps ...*remediationv1.Step) ([]*remediationv1.ExecutionEvent, error) {
	t.Helper()

	handler := NewRemediationHandler(WithRemediationLocalMode())
	handler.execStep = rec.run
	client := newRemediationTestClient(t, handler)

	steps := []*remediationv1.Step{
		{Id: "step-1", Title: "bump widget", Command: "go get example.com/widget@v1.5.0", Manager: "go", Executable: true},
		{Id: "step-2", Title: "bump gadget", Command: "go get example.com/gadget@v2.0.1", Manager: "go", Executable: true},
	}
	plan := &remediationv1.Plan{
		Id:    "plan-test",
		Steps: append(steps, extraSteps...),
	}

	stream, err := client.ExecutePlan(t.Context(), connect.NewRequest(&remediationv1.ExecutePlanRequest{
		Source:     &remediationv1.ExecutePlanRequest_Plan{Plan: plan},
		TargetPath: t.TempDir(),
		Options:    options,
	}))
	if err != nil {
		return nil, err
	}
	var events []*remediationv1.ExecutionEvent
	for stream.Receive() {
		events = append(events, stream.Msg())
	}
	return events, stream.Err()
}

// TestExecutePlanExecutionOptions pins the request contract for ExecutePlan:
// dry runs never execute, unsupported approval modes are refused loudly
// instead of silently auto-executing, and skip_step_ids is honored.
func TestExecutePlanExecutionOptions(t *testing.T) {
	tests := []struct {
		name           string
		options        *remediationv1.ExecutionOptions
		extraSteps     []*remediationv1.Step
		failSteps      []string     // step IDs the recorder reports as failed
		wantCode       connect.Code // zero means the stream must succeed
		wantExecuted   []string
		wantMessages   []string                     // substrings that must appear across event messages
		wantMissing    []string                     // substrings that must NOT appear in any event message
		wantFinalPhase remediationv1.ExecutionPhase // zero means COMPLETED
	}{
		{
			name:         "nil options executes every step",
			options:      nil,
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{"Successfully executed 2 steps"},
		},
		{
			name:         "auto approve executes every step",
			options:      &remediationv1.ExecutionOptions{ApprovalMode: remediationv1.ApprovalMode_APPROVAL_MODE_AUTO_APPROVE},
			wantExecuted: []string{"step-1", "step-2"},
		},
		{
			name:         "dry run executes nothing",
			options:      &remediationv1.ExecutionOptions{DryRun: true},
			wantExecuted: nil,
			wantMessages: []string{
				"[dry run] Step 1/2 would execute: go get example.com/widget@v1.5.0",
				"[dry run] Step 2/2 would execute: go get example.com/gadget@v2.0.1",
				"Dry run complete: 2 steps would execute, nothing was changed",
			},
		},
		{
			name:     "interactive approval mode is rejected",
			options:  &remediationv1.ExecutionOptions{ApprovalMode: remediationv1.ApprovalMode_APPROVAL_MODE_INTERACTIVE},
			wantCode: connect.CodeUnimplemented,
		},
		{
			name:     "all steps approval mode is rejected",
			options:  &remediationv1.ExecutionOptions{ApprovalMode: remediationv1.ApprovalMode_APPROVAL_MODE_ALL_STEPS},
			wantCode: connect.CodeUnimplemented,
		},
		{
			name:     "skip high risk approval mode is rejected",
			options:  &remediationv1.ExecutionOptions{ApprovalMode: remediationv1.ApprovalMode_APPROVAL_MODE_SKIP_HIGH_RISK},
			wantCode: connect.CodeUnimplemented,
		},
		{
			name:         "skip_step_ids skips the listed step",
			options:      &remediationv1.ExecutionOptions{SkipStepIds: []string{"step-1"}},
			wantExecuted: []string{"step-2"},
			wantMessages: []string{
				"Skipped step 1/2 (requested via skip_step_ids)",
				"Successfully executed 1 steps (1 skipped)",
			},
		},
		{
			name:         "dry run honors skip_step_ids",
			options:      &remediationv1.ExecutionOptions{DryRun: true, SkipStepIds: []string{"step-2"}},
			wantExecuted: nil,
			wantMessages: []string{
				"[dry run] Step 1/2 would execute",
				"Dry run complete: 1 steps would execute, nothing was changed (1 skipped)",
			},
		},
		{
			name:     "negative timeout is rejected",
			options:  &remediationv1.ExecutionOptions{Timeout: durationpb.New(-time.Second)},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "malformed timeout is rejected",
			options:  &remediationv1.ExecutionOptions{Timeout: &durationpb.Duration{Seconds: 1, Nanos: -1}},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "expired timeout aborts a dry run",
			options:  &remediationv1.ExecutionOptions{DryRun: true, Timeout: durationpb.New(time.Nanosecond)},
			wantCode: connect.CodeDeadlineExceeded,
		},
		{
			name:    "dry run counts only executable steps",
			options: &remediationv1.ExecutionOptions{DryRun: true},
			extraSteps: []*remediationv1.Step{
				{Id: "step-3", Title: "manual review", Command: "review the dependency change", Executable: false},
			},
			wantExecuted: nil,
			wantMessages: []string{
				"[dry run] Step 3/3 is manual: review the dependency change",
				"Dry run complete: 2 steps would execute, nothing was changed",
			},
		},
		{
			name:    "manual step is reported skipped not completed",
			options: nil,
			extraSteps: []*remediationv1.Step{
				{Id: "step-3", Title: "migrate to the maintained module", Command: "replace example.com/old with example.com/new", Executable: false},
			},
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{
				"Skipped step 3/3 (manual step): replace example.com/old with example.com/new",
				"Successfully executed 2 steps (1 skipped)",
			},
			wantMissing: []string{"Completed step 3/3"},
		},
		{
			name:    "manual step is reported skipped in verbose mode too",
			options: &remediationv1.ExecutionOptions{VerboseOutput: true},
			extraSteps: []*remediationv1.Step{
				{Id: "step-3", Title: "migrate to the maintained module", Command: "replace example.com/old with example.com/new", Executable: false},
			},
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{
				"Skipped step 3/3 (manual step): replace example.com/old with example.com/new",
				"Successfully executed 2 steps (1 skipped)",
			},
			wantMissing: []string{"Completed step 3/3"},
		},
		{
			name:    "commandless step is reported skipped",
			options: nil,
			extraSteps: []*remediationv1.Step{
				{Id: "step-3", Title: "nothing to do", Executable: true},
			},
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{
				"Skipped step 3/3 (no command): nothing to do",
				"Successfully executed 2 steps (1 skipped)",
			},
			wantMissing: []string{"Completed step 3/3"},
		},
		{
			name:         "stop_on_error true halts at the first failure",
			options:      &remediationv1.ExecutionOptions{StopOnError: true},
			failSteps:    []string{"step-1"},
			wantCode:     connect.CodeInternal,
			wantExecuted: []string{"step-1"},
		},
		{
			name:         "failure without stop_on_error continues and reports honestly",
			options:      nil,
			failSteps:    []string{"step-1"},
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{
				"Step failed: simulated step failure",
				"failure output",
				"Executed 2 steps: 1 succeeded, 1 failed",
			},
			wantFinalPhase: remediationv1.ExecutionPhase_EXECUTION_PHASE_FAILED,
		},
		{
			name:         "non-verbose completion summarizes without command output",
			options:      nil,
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{
				"Completed step 1/2: go get example.com/widget@v1.5.0",
			},
			wantMissing: []string{"recorded output"},
		},
		{
			name:         "verbose completion includes command output",
			options:      &remediationv1.ExecutionOptions{VerboseOutput: true},
			wantExecuted: []string{"step-1", "step-2"},
			wantMessages: []string{"recorded output"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &stepRecorder{failSteps: tt.failSteps}
			events, err := executePlanForTest(t, rec, tt.options, tt.extraSteps...)

			if got := rec.executedSteps(); !slices.Equal(got, tt.wantExecuted) {
				t.Fatalf("executed steps = %v, want %v", got, tt.wantExecuted)
			}
			if tt.wantCode != 0 {
				if connect.CodeOf(err) != tt.wantCode {
					t.Fatalf("ExecutePlan error = %v, want code %v", err, tt.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExecutePlan failed: %v", err)
			}

			var messages []string
			for _, ev := range events {
				messages = append(messages, ev.GetMessage())
			}
			all := strings.Join(messages, "\n")
			for _, want := range tt.wantMessages {
				if !strings.Contains(all, want) {
					t.Errorf("event messages missing %q:\n%s", want, all)
				}
			}
			for _, missing := range tt.wantMissing {
				if strings.Contains(all, missing) {
					t.Errorf("event messages must not contain %q:\n%s", missing, all)
				}
			}
			wantFinal := tt.wantFinalPhase
			if wantFinal == remediationv1.ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED {
				wantFinal = remediationv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED
			}
			last := events[len(events)-1]
			if last.GetPhase() != wantFinal {
				t.Errorf("final phase = %v, want %v", last.GetPhase(), wantFinal)
			}
		})
	}
}

// TestExecutePlanReportsProgress pins the ExecutionEvent progress contract:
// step events carry the 0-100 completion percentage instead of leaving the
// field at zero.
func TestExecutePlanReportsProgress(t *testing.T) {
	rec := &stepRecorder{}
	events, err := executePlanForTest(t, rec, nil)
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}

	var got []int32
	for _, ev := range events {
		got = append(got, ev.GetProgress())
	}
	// PREPARING, step-1 start, step-1 done, step-2 start, step-2 done, COMPLETED.
	want := []int32{0, 0, 50, 50, 100, 100}
	if !slices.Equal(got, want) {
		t.Fatalf("progress sequence = %v, want %v", got, want)
	}
}

// TestExecutePlanTimeout pins that a requested execution timeout reaches the
// step execution context as a deadline, and that no deadline is imposed when
// the option is absent.
func TestExecutePlanTimeout(t *testing.T) {
	tests := []struct {
		name         string
		options      *remediationv1.ExecutionOptions
		wantDeadline bool
	}{
		{
			name:         "timeout wraps the execution context",
			options:      &remediationv1.ExecutionOptions{Timeout: durationpb.New(time.Minute)},
			wantDeadline: true,
		},
		{
			name:         "no timeout leaves the context unbounded",
			options:      nil,
			wantDeadline: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &stepRecorder{}
			if _, err := executePlanForTest(t, rec, tt.options); err != nil {
				t.Fatalf("ExecutePlan failed: %v", err)
			}
			if rec.hadDeadline != tt.wantDeadline {
				t.Fatalf("step context deadline = %v, want %v", rec.hadDeadline, tt.wantDeadline)
			}
		})
	}
}

// TestExecutePlanExpiredTimeoutCode pins error code fidelity: a step stopped
// by the client-requested timeout must surface as CodeDeadlineExceeded, not
// CodeInternal, so clients can tell their own limit from a server failure.
// The plan uses a deputy-internal step and the real executeStep so the whole
// path (timeout wrap, pre-step check, code mapping) is exercised end to end.
func TestExecutePlanExpiredTimeoutCode(t *testing.T) {
	handler := NewRemediationHandler(WithRemediationLocalMode())
	client := newRemediationTestClient(t, handler)

	plan := &remediationv1.Plan{
		Id: "plan-timeout",
		Steps: []*remediationv1.Step{
			{Id: "step-1", Title: "update checkout action", Command: "deputy:action:update .github/workflows/ci.yml actions/checkout v5", Executable: true},
		},
	}
	stream, err := client.ExecutePlan(t.Context(), connect.NewRequest(&remediationv1.ExecutePlanRequest{
		Source:     &remediationv1.ExecutePlanRequest_Plan{Plan: plan},
		TargetPath: t.TempDir(),
		Options:    &remediationv1.ExecutionOptions{Timeout: durationpb.New(time.Nanosecond)},
	}))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("ExecutePlan error = %v (code %v), want CodeDeadlineExceeded", err, got)
	}
}

// TestExecutePlanEmptyPlanExpiredTimeout pins that the zero-step branch is
// not a timeout bypass: a plan with no steps must not report COMPLETED under
// an already-expired execution timeout.
func TestExecutePlanEmptyPlanExpiredTimeout(t *testing.T) {
	handler := NewRemediationHandler(WithRemediationLocalMode())
	client := newRemediationTestClient(t, handler)

	stream, err := client.ExecutePlan(t.Context(), connect.NewRequest(&remediationv1.ExecutePlanRequest{
		Source:     &remediationv1.ExecutePlanRequest_Plan{Plan: &remediationv1.Plan{Id: "plan-empty"}},
		TargetPath: t.TempDir(),
		Options:    &remediationv1.ExecutionOptions{Timeout: durationpb.New(time.Nanosecond)},
	}))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("ExecutePlan error = %v (code %v), want CodeDeadlineExceeded", err, got)
	}
}

// TestExecutePlanMidCommandTimeoutCode pins error code fidelity for
// timeouts that expire while a command is running: exec.CommandContext kills
// the process and reports an exit error (signal: killed) that does not wrap
// the context sentinel, so the failure path must consult the context to
// report CodeDeadlineExceeded instead of CodeInternal. Uses a real sleeping
// `go run` command so the kill path is exercised end to end.
func TestExecutePlanMidCommandTimeoutCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module sleeper\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatalf("WriteFile go.mod failed: %v", err)
	}
	// Keep the sleep short: `go run` is the process that gets killed, and its
	// compiled child holds the output pipes until it exits on its own, so the
	// sleep bounds how long CombinedOutput blocks after the kill.
	main := "package main\n\nimport \"time\"\n\nfunc main() { time.Sleep(5 * time.Second) }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644); err != nil {
		t.Fatalf("WriteFile main.go failed: %v", err)
	}

	handler := NewRemediationHandler(WithRemediationLocalMode())
	client := newRemediationTestClient(t, handler)

	plan := &remediationv1.Plan{
		Id: "plan-sleeper",
		Steps: []*remediationv1.Step{
			{Id: "step-1", Title: "sleep", Command: "go run .", Manager: "go", Executable: true},
		},
	}
	stream, err := client.ExecutePlan(t.Context(), connect.NewRequest(&remediationv1.ExecutePlanRequest{
		Source:     &remediationv1.ExecutePlanRequest_Plan{Plan: plan},
		TargetPath: dir,
		Options:    &remediationv1.ExecutionOptions{Timeout: durationpb.New(1500 * time.Millisecond)},
	}))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("ExecutePlan error = %v (code %v), want CodeDeadlineExceeded", err, got)
	}
}

// TestExecuteStepRespectsCancellation pins the timeout contract for
// deputy-internal steps: ApplyDeputyCommand edits files without a context,
// so an expired deadline must stop the step before any modification. The
// same step under a live context is the positive control proving the step
// would otherwise modify the file.
func TestExecuteStepRespectsCancellation(t *testing.T) {
	const original = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
	writeWorkflow := func(t *testing.T) (dir, path string) {
		t.Helper()
		dir = t.TempDir()
		wfDir := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		path = filepath.Join(wfDir, "ci.yml")
		if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
		return dir, path
	}
	step := &remediationv1.Step{
		Id:         "step-1",
		Title:      "update checkout action",
		Command:    "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
		Executable: true,
	}

	t.Run("expired deadline modifies nothing", func(t *testing.T) {
		dir, path := writeWorkflow(t)
		ctx, cancel := context.WithTimeout(t.Context(), -time.Second)
		defer cancel()

		if _, err := executeStep(ctx, dir, step); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("executeStep error = %v, want context.DeadlineExceeded", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if string(got) != original {
			t.Fatalf("workflow modified despite expired deadline:\n%s", got)
		}
	})

	t.Run("live context applies the update", func(t *testing.T) {
		dir, path := writeWorkflow(t)
		if _, err := executeStep(t.Context(), dir, step); err != nil {
			t.Fatalf("executeStep failed: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if !strings.Contains(string(got), "actions/checkout@v5") {
			t.Fatalf("workflow not updated, positive control is vacuous:\n%s", got)
		}
	})
}

// TestConvertAgentDoneEvent pins the Done event conversion: token usage must
// not overwrite the terminal summary; both are emitted, tokens first with a
// nonterminal phase so the summary is the first terminal event consumers see.
func TestConvertAgentDoneEvent(t *testing.T) {
	doneWithUsage := &agentv1.ExecuteEvent{
		Phase: agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Details: &agentv1.ExecuteEvent_Done{
			Done: &agentv1.DoneEvent{
				SessionId: "agent-sess",
				Reason:    agentv1.DoneReason_DONE_REASON_SUCCESS,
				Usage: &agentv1.TokenUsage{
					PromptTokens:     100,
					CompletionTokens: 25,
					TotalTokens:      125,
				},
			},
		},
	}

	events := convertAgentEventToRemediationEvents(doneWithUsage, "sess-1")
	if len(events) != 2 {
		t.Fatalf("converted events = %d, want 2 (tokens then summary)", len(events))
	}
	tokens := events[0].GetTokens()
	if tokens == nil {
		t.Fatalf("first event details = %T, want tokens", events[0].GetDetails())
	}
	if tokens.GetTotalTokens() != 125 || tokens.GetPromptTokens() != 100 || tokens.GetCompletionTokens() != 25 {
		t.Errorf("tokens event = %+v, want 100/25/125", tokens)
	}
	if phase := events[0].GetPhase(); internalproto.IsAgentTerminal(phase) {
		t.Errorf("tokens event phase %v is terminal; consumers would stop before the summary", phase)
	}
	summary := events[1].GetSummary()
	if summary == nil {
		t.Fatalf("second event details = %T, want summary", events[1].GetDetails())
	}
	if !summary.GetSuccess() || summary.GetSessionId() != "agent-sess" {
		t.Errorf("summary event = %+v, want success for agent-sess", summary)
	}
	if phase := events[1].GetPhase(); !internalproto.IsAgentTerminal(phase) {
		t.Errorf("summary event phase %v is not terminal", phase)
	}
	if last := events[len(events)-1]; last.GetSummary() == nil {
		t.Errorf("last event details = %T, want summary last", last.GetDetails())
	}

	doneWithoutUsage := &agentv1.ExecuteEvent{
		Phase: agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		Details: &agentv1.ExecuteEvent_Done{
			Done: &agentv1.DoneEvent{Reason: agentv1.DoneReason_DONE_REASON_SUCCESS},
		},
	}
	events = convertAgentEventToRemediationEvents(doneWithoutUsage, "sess-1")
	if len(events) != 1 {
		t.Fatalf("converted events = %d, want 1", len(events))
	}
	if events[0].GetSummary() == nil {
		t.Fatalf("event details = %T, want summary", events[0].GetDetails())
	}
}

// TestApproveStepCanProceed pins the ApproveStepResponse contract: a
// delivered approval reports can_proceed matching the decision, and a
// session with no pending approval is refused without claiming progress.
func TestApproveStepCanProceed(t *testing.T) {
	tests := []struct {
		name           string
		approved       bool
		fillChannel    bool
		wantAccepted   bool
		wantCanProceed bool
	}{
		{name: "accepted approval can proceed", approved: true, wantAccepted: true, wantCanProceed: true},
		{name: "accepted denial cannot proceed", approved: false, wantAccepted: true, wantCanProceed: false},
		{name: "no pending approval is refused", approved: true, fillChannel: true, wantAccepted: false, wantCanProceed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewRemediationHandler()
			session := &agentSession{approvals: make(chan *agentv1.ApproveRequest, 1)}
			handler.sessions["sess-1"] = session
			if tt.fillChannel {
				session.approvals <- &agentv1.ApproveRequest{}
			}

			resp, err := handler.ApproveStep(t.Context(), connect.NewRequest(&remediationv1.ApproveStepRequest{
				SessionId: "sess-1",
				StepId:    "step-1",
				Approved:  tt.approved,
			}))
			if err != nil {
				t.Fatalf("ApproveStep failed: %v", err)
			}
			if got := resp.Msg.GetAccepted(); got != tt.wantAccepted {
				t.Errorf("accepted = %v, want %v", got, tt.wantAccepted)
			}
			if got := resp.Msg.GetCanProceed(); got != tt.wantCanProceed {
				t.Errorf("can_proceed = %v, want %v", got, tt.wantCanProceed)
			}
		})
	}
}

// fakeAgentHandler is a minimal agent plugin reporting fixed capabilities so
// ListAgents mapping can be asserted without real agent binaries.
type fakeAgentHandler struct {
	agentv1connect.UnimplementedAgentPluginHandler
	name string
	caps *agentv1.AgentCapabilities
}

// GetInfo reports the fake agent's identity and configured capabilities.
func (f *fakeAgentHandler) GetInfo(context.Context, *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return connect.NewResponse(&agentv1.GetInfoResponse{
		Name:         f.name,
		DisplayName:  f.name,
		Description:  "fake agent",
		Capabilities: f.caps,
	}), nil
}

// fakeExecutorAgentHandler is a fakeAgentHandler that also implements the
// in-process agent.Executor interface ExecuteWithAgent requires, standing in
// for builtin agents like claude and codex.
type fakeExecutorAgentHandler struct {
	fakeAgentHandler
}

// ExecuteIter satisfies agent.Executor with an empty event stream.
func (f *fakeExecutorAgentHandler) ExecuteIter(context.Context, *agentv1.ExecuteRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(func(*agentv1.ExecuteEvent, error) bool) {}
}

// ResumeIter satisfies agent.Executor with an empty event stream.
func (f *fakeExecutorAgentHandler) ResumeIter(context.Context, *agentv1.ResumeRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(func(*agentv1.ExecuteEvent, error) bool) {}
}

// fakeApprovalExecutorAgentHandler additionally declares working approval
// delivery via agent.ApprovalSupporter.
type fakeApprovalExecutorAgentHandler struct {
	fakeExecutorAgentHandler
}

// SupportsApprovals declares real approval delivery for the fake.
func (f *fakeApprovalExecutorAgentHandler) SupportsApprovals() bool { return true }

// TestListAgentsCapabilities pins the capability mapping: execution
// capabilities require local mode, the agentic flag, and in-process executor
// support (what ExecuteWithAgent actually requires), and approval workflows
// additionally require an explicit agent.ApprovalSupporter declaration, since
// every handler structurally has an Approve method.
func TestListAgentsCapabilities(t *testing.T) {
	agenticCaps := &agentv1.AgentCapabilities{
		Streaming:         true,
		ToolUse:           true,
		Agentic:           true,
		SessionResumption: true,
	}
	tests := []struct {
		name      string
		handler   agentv1connect.AgentPluginHandler
		localMode bool
		want      *remediationv1.AgentCapabilities
	}{
		{
			name:      "agentic executor without approval declaration",
			handler:   &fakeExecutorAgentHandler{fakeAgentHandler{name: "fake", caps: agenticCaps}},
			localMode: true,
			want: &remediationv1.AgentCapabilities{
				Streaming:         true,
				ToolUse:           true,
				Agentic:           true,
				SessionResumption: true,
				CodeExecution:     true,
				FileModification:  true,
			},
		},
		{
			name:      "agentic executor declaring approval support",
			handler:   &fakeApprovalExecutorAgentHandler{fakeExecutorAgentHandler{fakeAgentHandler{name: "fake", caps: agenticCaps}}},
			localMode: true,
			want: &remediationv1.AgentCapabilities{
				Streaming:         true,
				ToolUse:           true,
				Agentic:           true,
				SessionResumption: true,
				CodeExecution:     true,
				FileModification:  true,
				ApprovalWorkflows: true,
			},
		},
		{
			name:      "agentic non-executor advertises no execution capabilities",
			handler:   &fakeAgentHandler{name: "fake", caps: agenticCaps},
			localMode: true,
			want: &remediationv1.AgentCapabilities{
				Streaming:         true,
				ToolUse:           true,
				Agentic:           true,
				SessionResumption: true,
			},
		},
		{
			name:      "non-agentic executor advertises no execution capabilities",
			handler:   &fakeExecutorAgentHandler{fakeAgentHandler{name: "fake", caps: &agentv1.AgentCapabilities{Streaming: true}}},
			localMode: true,
			want:      &remediationv1.AgentCapabilities{Streaming: true},
		},
		{
			name:      "remote mode advertises no execution capabilities",
			handler:   &fakeApprovalExecutorAgentHandler{fakeExecutorAgentHandler{fakeAgentHandler{name: "fake", caps: agenticCaps}}},
			localMode: false,
			want: &remediationv1.AgentCapabilities{
				Streaming:         true,
				ToolUse:           true,
				Agentic:           true,
				SessionResumption: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := agent.NewRegistry()
			if err := registry.RegisterBuiltin("fake", tt.handler); err != nil {
				t.Fatalf("RegisterBuiltin failed: %v", err)
			}
			handlerOpts := []RemediationHandlerOption{WithRemediationRegistry(registry)}
			if tt.localMode {
				handlerOpts = append(handlerOpts, WithRemediationLocalMode())
			}
			handler := NewRemediationHandler(handlerOpts...)

			resp, err := handler.ListAgents(t.Context(), connect.NewRequest(&remediationv1.ListAgentsRequest{}))
			if err != nil {
				t.Fatalf("ListAgents failed: %v", err)
			}
			agents := resp.Msg.GetAgents()
			if len(agents) != 1 {
				t.Fatalf("agents = %d, want 1", len(agents))
			}
			got := agents[0].GetCapabilities()
			checks := []struct {
				field string
				got   bool
				want  bool
			}{
				{"streaming", got.GetStreaming(), tt.want.GetStreaming()},
				{"tool_use", got.GetToolUse(), tt.want.GetToolUse()},
				{"agentic", got.GetAgentic(), tt.want.GetAgentic()},
				{"session_resumption", got.GetSessionResumption(), tt.want.GetSessionResumption()},
				{"code_execution", got.GetCodeExecution(), tt.want.GetCodeExecution()},
				{"file_modification", got.GetFileModification(), tt.want.GetFileModification()},
				{"approval_workflows", got.GetApprovalWorkflows(), tt.want.GetApprovalWorkflows()},
			}
			for _, c := range checks {
				if c.got != c.want {
					t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
				}
			}
		})
	}
}
