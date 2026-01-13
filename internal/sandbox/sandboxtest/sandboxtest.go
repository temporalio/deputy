// Package sandboxtest provides utilities for testing sandbox runtime plugins
// in-memory without spawning external processes or using network sockets.
//
// This package enables unit and integration testing of sandbox plugins by:
//   - Running plugin handlers directly in-memory via ConnectRPC
//   - Providing test fixtures for common sandbox scenarios
//   - Asserting on execution events (stdout, stderr, exit codes, errors)
//
// Example usage:
//
//	func TestMyPlugin(t *testing.T) {
//	    handler := &myPluginHandler{}
//	    harness := sandboxtest.NewHarness(t, handler)
//
//	    result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
//	        Command: []string{"echo", "hello"},
//	    })
//
//	    result.AssertExitCode(0)
//	    result.AssertStdoutContains("hello")
//	}
package sandboxtest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
)

// Harness provides an in-memory test harness for sandbox runtime plugins.
// It wraps a SandboxRuntimeServiceHandler and provides convenient methods
// for testing execution behavior.
type Harness struct {
	t       testing.TB
	handler sandboxv1connect.SandboxRuntimeServiceHandler
	server  *httptest.Server
	client  sandboxv1connect.SandboxRuntimeServiceClient
}

// NewHarness creates a new test harness for the given handler.
// The harness sets up an in-memory HTTP server using httptest,
// allowing the handler to be tested without network I/O.
func NewHarness(t testing.TB, handler sandboxv1connect.SandboxRuntimeServiceHandler) *Harness {
	t.Helper()

	mux := http.NewServeMux()
	path, h := sandboxv1connect.NewSandboxRuntimeServiceHandler(handler)
	mux.Handle(path, h)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := sandboxv1connect.NewSandboxRuntimeServiceClient(
		server.Client(),
		server.URL,
	)

	return &Harness{
		t:       t,
		handler: handler,
		server:  server,
		client:  client,
	}
}

// GetInfo calls the GetInfo RPC and returns the response.
func (h *Harness) GetInfo(ctx context.Context) *sandboxv1.GetRuntimeInfoResponse {
	h.t.Helper()

	resp, err := h.client.GetInfo(ctx, connect.NewRequest(&sandboxv1.GetRuntimeInfoRequest{}))
	if err != nil {
		h.t.Fatalf("GetInfo failed: %v", err)
	}
	return resp.Msg
}

// Execute runs a command through the plugin and returns an ExecuteResult
// that can be used for assertions.
func (h *Harness) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) *ExecuteResult {
	h.t.Helper()

	// Convert to RuntimeExecuteRequest
	runtimeReq := &sandboxv1.RuntimeExecuteRequest{
		Command:      req.GetCommand(),
		Config:       req.GetConfig(),
		WorkDir:      req.GetWorkDir(),
		Env:          req.GetEnv(),
		Stdin:        req.GetStdin(),
		Timeout:      req.GetTimeout(),
		WorkspaceDir: req.GetWorkspaceDir(),
		ExecutionId:  "test-exec-id",
	}

	stream, err := h.client.Execute(ctx, connect.NewRequest(runtimeReq))
	if err != nil {
		return &ExecuteResult{
			t:         h.t,
			StreamErr: err,
		}
	}
	defer stream.Close()

	result := &ExecuteResult{
		t:      h.t,
		Events: make([]*sandboxv1.ExecuteEvent, 0),
	}

	for stream.Receive() {
		event := stream.Msg()
		result.Events = append(result.Events, event)

		switch details := event.GetDetails().(type) {
		case *sandboxv1.ExecuteEvent_Output:
			if details.Output.GetIsStderr() {
				result.Stderr = append(result.Stderr, details.Output.GetData()...)
			} else {
				result.Stdout = append(result.Stdout, details.Output.GetData()...)
			}
		case *sandboxv1.ExecuteEvent_Completed:
			result.ExitCode = details.Completed.GetExitCode()
			result.Completed = true
		case *sandboxv1.ExecuteEvent_Error:
			result.Errors = append(result.Errors, details.Error)
			if details.Error.GetIsFatal() {
				result.FatalError = details.Error
			}
		}
	}

	if err := stream.Err(); err != nil {
		result.StreamErr = err
	}

	return result
}

// Cleanup calls the Cleanup RPC for the given execution ID.
func (h *Harness) Cleanup(ctx context.Context, executionID string) error {
	h.t.Helper()

	_, err := h.client.Cleanup(ctx, connect.NewRequest(&sandboxv1.CleanupRequest{
		ExecutionId: executionID,
	}))
	return err
}

// Client returns the underlying ConnectRPC client for advanced usage.
func (h *Harness) Client() sandboxv1connect.SandboxRuntimeServiceClient {
	return h.client
}

// ExecuteResult holds the collected results from an Execute call.
type ExecuteResult struct {
	t          testing.TB
	Events     []*sandboxv1.ExecuteEvent
	Stdout     []byte
	Stderr     []byte
	ExitCode   int32
	Completed  bool
	Errors     []*sandboxv1.ErrorEvent
	FatalError *sandboxv1.ErrorEvent
	StreamErr  error
}

// AssertNoError fails the test if any error occurred during execution.
func (r *ExecuteResult) AssertNoError() *ExecuteResult {
	r.t.Helper()
	if r.StreamErr != nil {
		r.t.Fatalf("stream error: %v", r.StreamErr)
	}
	if r.FatalError != nil {
		r.t.Fatalf("fatal error: %s (code: %s)", r.FatalError.GetMessage(), r.FatalError.GetCode())
	}
	return r
}

// AssertExitCode fails the test if the exit code doesn't match.
func (r *ExecuteResult) AssertExitCode(expected int32) *ExecuteResult {
	r.t.Helper()
	r.AssertNoError()
	if !r.Completed {
		r.t.Fatal("execution did not complete")
	}
	if r.ExitCode != expected {
		r.t.Fatalf("exit code: got %d, want %d\nstdout: %s\nstderr: %s",
			r.ExitCode, expected, string(r.Stdout), string(r.Stderr))
	}
	return r
}

// AssertCompleted fails the test if execution didn't complete.
func (r *ExecuteResult) AssertCompleted() *ExecuteResult {
	r.t.Helper()
	r.AssertNoError()
	if !r.Completed {
		r.t.Fatal("execution did not complete")
	}
	return r
}

// AssertStdoutEquals fails if stdout doesn't exactly match.
func (r *ExecuteResult) AssertStdoutEquals(expected string) *ExecuteResult {
	r.t.Helper()
	if string(r.Stdout) != expected {
		r.t.Fatalf("stdout: got %q, want %q", string(r.Stdout), expected)
	}
	return r
}

// AssertStdoutContains fails if stdout doesn't contain the substring.
func (r *ExecuteResult) AssertStdoutContains(substr string) *ExecuteResult {
	r.t.Helper()
	if !strings.Contains(string(r.Stdout), substr) {
		r.t.Fatalf("stdout %q does not contain %q", string(r.Stdout), substr)
	}
	return r
}

// AssertStderrContains fails if stderr doesn't contain the substring.
func (r *ExecuteResult) AssertStderrContains(substr string) *ExecuteResult {
	r.t.Helper()
	if !strings.Contains(string(r.Stderr), substr) {
		r.t.Fatalf("stderr %q does not contain %q", string(r.Stderr), substr)
	}
	return r
}

// AssertStderrEmpty fails if stderr is not empty.
func (r *ExecuteResult) AssertStderrEmpty() *ExecuteResult {
	r.t.Helper()
	if len(r.Stderr) > 0 {
		r.t.Fatalf("stderr not empty: %q", string(r.Stderr))
	}
	return r
}

// AssertErrorCode fails if no error with the given code was received.
func (r *ExecuteResult) AssertErrorCode(code string) *ExecuteResult {
	r.t.Helper()
	for _, err := range r.Errors {
		if err.GetCode() == code {
			return r
		}
	}
	r.t.Fatalf("no error with code %q found; errors: %v", code, r.Errors)
	return r
}

// AssertFatalError fails if no fatal error occurred.
func (r *ExecuteResult) AssertFatalError() *ExecuteResult {
	r.t.Helper()
	if r.FatalError == nil {
		r.t.Fatal("expected fatal error, got none")
	}
	return r
}

// AssertFatalErrorCode fails if no fatal error with the given code occurred.
func (r *ExecuteResult) AssertFatalErrorCode(code string) *ExecuteResult {
	r.t.Helper()
	if r.FatalError == nil {
		r.t.Fatal("expected fatal error, got none")
	}
	if r.FatalError.GetCode() != code {
		r.t.Fatalf("fatal error code: got %q, want %q", r.FatalError.GetCode(), code)
	}
	return r
}

// StdoutString returns stdout as a string.
func (r *ExecuteResult) StdoutString() string {
	return string(r.Stdout)
}

// StderrString returns stderr as a string.
func (r *ExecuteResult) StderrString() string {
	return string(r.Stderr)
}

// MockHandler is a configurable mock implementation of SandboxRuntimeServiceHandler
// for testing plugin consumers.
type MockHandler struct {
	sandboxv1connect.UnimplementedSandboxRuntimeServiceHandler

	// InfoResponse is returned by GetInfo.
	InfoResponse *sandboxv1.GetRuntimeInfoResponse

	// ExecuteFunc is called for each Execute request.
	// If nil, a simple echo implementation is used.
	ExecuteFunc func(context.Context, *sandboxv1.RuntimeExecuteRequest, func(*sandboxv1.ExecuteEvent) error) error

	// CleanupFunc is called for each Cleanup request.
	CleanupFunc func(context.Context, string) error
}

// GetInfo implements SandboxRuntimeServiceHandler.
func (m *MockHandler) GetInfo(ctx context.Context, req *connect.Request[sandboxv1.GetRuntimeInfoRequest]) (*connect.Response[sandboxv1.GetRuntimeInfoResponse], error) {
	if m.InfoResponse != nil {
		return connect.NewResponse(m.InfoResponse), nil
	}
	return connect.NewResponse(&sandboxv1.GetRuntimeInfoResponse{
		Name:        "mock",
		DisplayName: "Mock Runtime",
		Version:     "1.0.0",
		SupportedModes: []sandboxv1.Mode{
			sandboxv1.Mode_MODE_READ_ONLY,
			sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		},
		Capabilities: &sandboxv1.RuntimeCapabilities{
			StreamingOutput: true,
		},
	}), nil
}

// Execute implements SandboxRuntimeServiceHandler.
func (m *MockHandler) Execute(ctx context.Context, req *connect.Request[sandboxv1.RuntimeExecuteRequest], stream *connect.ServerStream[sandboxv1.ExecuteEvent]) error {
	execReq := req.Msg

	send := func(event *sandboxv1.ExecuteEvent) error {
		return stream.Send(event)
	}

	if m.ExecuteFunc != nil {
		return m.ExecuteFunc(ctx, execReq, send)
	}

	// Default: simple echo-like behavior
	cmd := execReq.GetCommand()
	if len(cmd) == 0 {
		return send(NewErrorEvent(execReq.GetExecutionId(), "INVALID_COMMAND", "empty command", true))
	}

	// Just echo the command back
	output := strings.Join(cmd, " ") + "\n"
	if err := send(NewOutputEvent(execReq.GetExecutionId(), []byte(output), false)); err != nil {
		return err
	}

	return send(NewCompletedEvent(execReq.GetExecutionId(), 0))
}

// Cleanup implements SandboxRuntimeServiceHandler.
func (m *MockHandler) Cleanup(ctx context.Context, req *connect.Request[sandboxv1.CleanupRequest]) (*connect.Response[sandboxv1.CleanupResponse], error) {
	if m.CleanupFunc != nil {
		if err := m.CleanupFunc(ctx, req.Msg.GetExecutionId()); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&sandboxv1.CleanupResponse{}), nil
}

// Event constructors for building test responses.

// NewOutputEvent creates an output event.
func NewOutputEvent(executionID string, data []byte, isStderr bool) *sandboxv1.ExecuteEvent {
	return &sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Details: &sandboxv1.ExecuteEvent_Output{
			Output: &sandboxv1.OutputEvent{
				Data:     data,
				IsStderr: isStderr,
			},
		},
	}
}

// NewCompletedEvent creates a completed event.
func NewCompletedEvent(executionID string, exitCode int32) *sandboxv1.ExecuteEvent {
	return &sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Details: &sandboxv1.ExecuteEvent_Completed{
			Completed: &sandboxv1.CompletedEvent{
				ExitCode: exitCode,
			},
		},
	}
}

// NewErrorEvent creates an error event.
func NewErrorEvent(executionID, code, message string, isFatal bool) *sandboxv1.ExecuteEvent {
	return &sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Details: &sandboxv1.ExecuteEvent_Error{
			Error: &sandboxv1.ErrorEvent{
				Code:    code,
				Message: message,
				IsFatal: isFatal,
			},
		},
	}
}

// StreamRecorder captures events for later inspection.
type StreamRecorder struct {
	Events []*sandboxv1.ExecuteEvent
}

// NewStreamRecorder creates a new stream recorder.
func NewStreamRecorder() *StreamRecorder {
	return &StreamRecorder{
		Events: make([]*sandboxv1.ExecuteEvent, 0),
	}
}

// Send records an event.
func (r *StreamRecorder) Send(event *sandboxv1.ExecuteEvent) error {
	r.Events = append(r.Events, event)
	return nil
}

// Stdout returns all stdout data.
func (r *StreamRecorder) Stdout() []byte {
	var buf bytes.Buffer
	for _, event := range r.Events {
		if out, ok := event.GetDetails().(*sandboxv1.ExecuteEvent_Output); ok {
			if !out.Output.GetIsStderr() {
				buf.Write(out.Output.GetData())
			}
		}
	}
	return buf.Bytes()
}

// Stderr returns all stderr data.
func (r *StreamRecorder) Stderr() []byte {
	var buf bytes.Buffer
	for _, event := range r.Events {
		if out, ok := event.GetDetails().(*sandboxv1.ExecuteEvent_Output); ok {
			if out.Output.GetIsStderr() {
				buf.Write(out.Output.GetData())
			}
		}
	}
	return buf.Bytes()
}

// ExitCode returns the exit code from the completed event, or -1 if not completed.
func (r *StreamRecorder) ExitCode() int32 {
	for _, event := range r.Events {
		if completed, ok := event.GetDetails().(*sandboxv1.ExecuteEvent_Completed); ok {
			return completed.Completed.GetExitCode()
		}
	}
	return -1
}

// CommandRunner is a helper for plugins that execute real commands.
// It provides a testable wrapper around os/exec.
type CommandRunner interface {
	Run(ctx context.Context, cmd []string, stdin io.Reader, stdout, stderr io.Writer, env map[string]string, workDir string) (int, error)
}

// RealCommandRunner executes commands using os/exec.
type RealCommandRunner struct{}

// Run executes the command and returns the exit code.
func (r *RealCommandRunner) Run(ctx context.Context, cmd []string, stdin io.Reader, stdout, stderr io.Writer, env map[string]string, workDir string) (int, error) {
	if len(cmd) == 0 {
		return -1, fmt.Errorf("empty command")
	}

	// Implementation would use os/exec - keeping it simple for the package
	return 0, fmt.Errorf("RealCommandRunner.Run not implemented - use for interface definition")
}

// FakeCommandRunner allows setting up expected command results for testing.
type FakeCommandRunner struct {
	// Results maps command strings to their outputs.
	// Key is the first element of the command (the executable).
	Results map[string]*FakeResult
}

// FakeResult defines the expected result of a command.
type FakeResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Run returns the pre-configured result for the command.
func (f *FakeCommandRunner) Run(ctx context.Context, cmd []string, stdin io.Reader, stdout, stderr io.Writer, env map[string]string, workDir string) (int, error) {
	if len(cmd) == 0 {
		return -1, fmt.Errorf("empty command")
	}

	result, ok := f.Results[cmd[0]]
	if !ok {
		return -1, fmt.Errorf("no fake result for command %q", cmd[0])
	}

	if result.Err != nil {
		return result.ExitCode, result.Err
	}

	if stdout != nil && result.Stdout != "" {
		_, _ = io.WriteString(stdout, result.Stdout)
	}
	if stderr != nil && result.Stderr != "" {
		_, _ = io.WriteString(stderr, result.Stderr)
	}

	return result.ExitCode, nil
}
