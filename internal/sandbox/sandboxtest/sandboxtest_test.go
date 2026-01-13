// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

package sandboxtest_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
	"github.com/picatz/deputy/internal/sandbox/sandboxtest"
)

func TestHarness_GetInfo(t *testing.T) {
	t.Parallel()

	handler := &sandboxtest.MockHandler{
		InfoResponse: &sandboxv1.GetRuntimeInfoResponse{
			Name:        "test-runtime",
			DisplayName: "Test Runtime",
			Version:     "2.0.0",
		},
	}

	harness := sandboxtest.NewHarness(t, handler)
	info := harness.GetInfo(context.Background())

	if info.GetName() != "test-runtime" {
		t.Errorf("Name: got %q, want %q", info.GetName(), "test-runtime")
	}
	if info.GetVersion() != "2.0.0" {
		t.Errorf("Version: got %q, want %q", info.GetVersion(), "2.0.0")
	}
}

func TestHarness_Execute_Success(t *testing.T) {
	t.Parallel()

	handler := &sandboxtest.MockHandler{
		ExecuteFunc: func(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest, send func(*sandboxv1.ExecuteEvent) error) error {
			// Send stdout
			if err := send(sandboxtest.NewOutputEvent(req.GetExecutionId(), []byte("hello world\n"), false)); err != nil {
				return err
			}
			// Send completed
			return send(sandboxtest.NewCompletedEvent(req.GetExecutionId(), 0))
		},
	}

	harness := sandboxtest.NewHarness(t, handler)
	result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"echo", "hello", "world"},
	})

	result.
		AssertExitCode(0).
		AssertStdoutContains("hello world").
		AssertStderrEmpty()
}

func TestHarness_Execute_NonZeroExit(t *testing.T) {
	t.Parallel()

	handler := &sandboxtest.MockHandler{
		ExecuteFunc: func(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest, send func(*sandboxv1.ExecuteEvent) error) error {
			if err := send(sandboxtest.NewOutputEvent(req.GetExecutionId(), []byte("error: something failed\n"), true)); err != nil {
				return err
			}
			return send(sandboxtest.NewCompletedEvent(req.GetExecutionId(), 1))
		},
	}

	harness := sandboxtest.NewHarness(t, handler)
	result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"false"},
	})

	result.
		AssertCompleted().
		AssertExitCode(1).
		AssertStderrContains("something failed")
}

func TestHarness_Execute_FatalError(t *testing.T) {
	t.Parallel()

	handler := &sandboxtest.MockHandler{
		ExecuteFunc: func(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest, send func(*sandboxv1.ExecuteEvent) error) error {
			return send(sandboxtest.NewErrorEvent(req.GetExecutionId(), "COMMAND_NOT_FOUND", "command not found: xyz", true))
		},
	}

	harness := sandboxtest.NewHarness(t, handler)
	result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"xyz"},
	})

	result.
		AssertFatalError().
		AssertFatalErrorCode("COMMAND_NOT_FOUND")
}

func TestHarness_Execute_DefaultMockBehavior(t *testing.T) {
	t.Parallel()

	// MockHandler with no ExecuteFunc uses default echo behavior
	handler := &sandboxtest.MockHandler{}

	harness := sandboxtest.NewHarness(t, handler)
	result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"echo", "test"},
	})

	result.
		AssertExitCode(0).
		AssertStdoutContains("echo test")
}

func TestStreamRecorder(t *testing.T) {
	t.Parallel()

	recorder := sandboxtest.NewStreamRecorder()

	// Record some events
	_ = recorder.Send(sandboxtest.NewOutputEvent("exec-1", []byte("stdout line 1\n"), false))
	_ = recorder.Send(sandboxtest.NewOutputEvent("exec-1", []byte("stderr line 1\n"), true))
	_ = recorder.Send(sandboxtest.NewOutputEvent("exec-1", []byte("stdout line 2\n"), false))
	_ = recorder.Send(sandboxtest.NewCompletedEvent("exec-1", 0))

	if got := string(recorder.Stdout()); got != "stdout line 1\nstdout line 2\n" {
		t.Errorf("Stdout: got %q", got)
	}
	if got := string(recorder.Stderr()); got != "stderr line 1\n" {
		t.Errorf("Stderr: got %q", got)
	}
	if got := recorder.ExitCode(); got != 0 {
		t.Errorf("ExitCode: got %d, want 0", got)
	}
}

func TestFakeCommandRunner(t *testing.T) {
	t.Parallel()

	runner := &sandboxtest.FakeCommandRunner{
		Results: map[string]*sandboxtest.FakeResult{
			"echo": {
				Stdout:   "hello\n",
				ExitCode: 0,
			},
			"false": {
				Stderr:   "error\n",
				ExitCode: 1,
			},
		},
	}

	var stdout, stderr strings.Builder

	// Test echo
	exitCode, err := runner.Run(context.Background(), []string{"echo", "hello"}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		t.Fatalf("Run(echo) error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("echo exit code: got %d, want 0", exitCode)
	}
	if got := stdout.String(); got != "hello\n" {
		t.Errorf("echo stdout: got %q, want %q", got, "hello\n")
	}

	// Reset and test false
	stdout.Reset()
	stderr.Reset()
	exitCode, err = runner.Run(context.Background(), []string{"false"}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		t.Fatalf("Run(false) error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("false exit code: got %d, want 1", exitCode)
	}
	if got := stderr.String(); got != "error\n" {
		t.Errorf("false stderr: got %q, want %q", got, "error\n")
	}
}

func TestFakeCommandRunner_UnknownCommand(t *testing.T) {
	t.Parallel()

	runner := &sandboxtest.FakeCommandRunner{
		Results: map[string]*sandboxtest.FakeResult{},
	}

	_, err := runner.Run(context.Background(), []string{"unknown"}, nil, nil, nil, nil, "")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

// ExamplePlugin demonstrates how to test a real plugin implementation.
type examplePlugin struct {
	sandboxv1connect.UnimplementedSandboxRuntimeServiceHandler
}

func (p *examplePlugin) GetInfo(ctx context.Context, req *connect.Request[sandboxv1.GetRuntimeInfoRequest]) (*connect.Response[sandboxv1.GetRuntimeInfoResponse], error) {
	return connect.NewResponse(&sandboxv1.GetRuntimeInfoResponse{
		Name:        "example",
		DisplayName: "Example Plugin",
		Version:     "1.0.0",
		SupportedModes: []sandboxv1.Mode{
			sandboxv1.Mode_MODE_READ_ONLY,
			sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		},
		Capabilities: &sandboxv1.RuntimeCapabilities{
			NetworkIsolation:    true,
			FilesystemIsolation: true,
			StreamingOutput:     true,
		},
	}), nil
}

func (p *examplePlugin) Execute(ctx context.Context, req *connect.Request[sandboxv1.RuntimeExecuteRequest], stream *connect.ServerStream[sandboxv1.ExecuteEvent]) error {
	execReq := req.Msg
	execID := execReq.GetExecutionId()
	cmd := execReq.GetCommand()

	if len(cmd) == 0 {
		return stream.Send(sandboxtest.NewErrorEvent(execID, "INVALID_COMMAND", "empty command", true))
	}

	// Simulate running echo
	if cmd[0] == "echo" {
		output := strings.Join(cmd[1:], " ") + "\n"
		if err := stream.Send(sandboxtest.NewOutputEvent(execID, []byte(output), false)); err != nil {
			return err
		}
		return stream.Send(sandboxtest.NewCompletedEvent(execID, 0))
	}

	return stream.Send(sandboxtest.NewErrorEvent(execID, "COMMAND_NOT_FOUND", "command not found: "+cmd[0], true))
}

func TestExamplePlugin(t *testing.T) {
	t.Parallel()

	harness := sandboxtest.NewHarness(t, &examplePlugin{})

	// Test GetInfo
	info := harness.GetInfo(context.Background())
	if info.GetName() != "example" {
		t.Errorf("Name: got %q, want %q", info.GetName(), "example")
	}
	if !info.GetCapabilities().GetNetworkIsolation() {
		t.Error("expected network isolation capability")
	}

	// Test successful execution
	result := harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"echo", "hello", "sandbox"},
	})
	result.
		AssertExitCode(0).
		AssertStdoutEquals("hello sandbox\n")

	// Test command not found
	result = harness.Execute(context.Background(), &sandboxv1.ExecuteRequest{
		Command: []string{"nonexistent"},
	})
	result.AssertFatalErrorCode("COMMAND_NOT_FOUND")
}
