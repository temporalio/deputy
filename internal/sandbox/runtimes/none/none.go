// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

// Package none provides a no-op sandbox runtime for trusted execution.
//
// The None runtime executes commands directly without any isolation.
// Use this for:
//   - Built-in plugins that are trusted
//   - Development and testing
//   - Environments where sandboxing is handled externally
//
// Warning: This provides NO isolation. Commands have full access to the system.
package none

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Runtime implements sandbox.Runtime with no isolation.
type Runtime struct{}

// New creates a new None runtime.
func New() *Runtime {
	return &Runtime{}
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_NONE.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_NONE
}

// Info returns metadata about the None runtime.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	return &sandboxv1.RuntimeInfo{
		Runtime:        sandboxv1.Runtime_RUNTIME_NONE,
		DisplayName:    "None (No Sandboxing)",
		Version:        "1.0.0",
		Available:      true,
		SupportedModes: r.supportedModes(),
		Capabilities:   r.Capabilities(),
	}, nil
}

// Available always returns true as no external dependencies are needed.
func (r *Runtime) Available(ctx context.Context) bool {
	return true
}

// Version returns a fixed version string.
func (r *Runtime) Version(ctx context.Context) string {
	return "1.0.0"
}

// Capabilities returns what this runtime supports.
// The None runtime provides no isolation capabilities.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    false,
		FilesystemIsolation: false,
		ResourceLimits:      false,
		Seccomp:             false,
		Apparmor:            false,
		Selinux:             false,
		UserNamespaces:      false,
		Rootless:            true, // Runs as current user
		GpuSupport:          true, // No restrictions
		StreamingOutput:     true,
		InteractiveStdin:    true,
	}
}

func (r *Runtime) supportedModes() []sandboxv1.Mode {
	// None runtime effectively provides full access regardless of mode
	return []sandboxv1.Mode{
		sandboxv1.Mode_MODE_FULL_ACCESS,
	}
}

// Execute runs a command directly without sandboxing.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := fmt.Sprintf("none-%d", time.Now().UnixNano())
		startTime := time.Now()

		// Validate request
		if len(req.GetCommand()) == 0 {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: "command is required",
						Code:    "INVALID_REQUEST",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		// Apply timeout from request if specified
		execCtx := ctx
		var cancel context.CancelFunc
		if timeout := req.GetTimeout(); timeout != nil && timeout.AsDuration() > 0 {
			execCtx, cancel = context.WithTimeout(ctx, timeout.AsDuration())
			defer cancel()
		}

		// Send started event
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Started{
				Started: &sandboxv1.StartedEvent{
					ExecutionId:     executionID,
					Runtime:         sandboxv1.Runtime_RUNTIME_NONE,
					EffectiveConfig: req.GetConfig(),
				},
			},
		}, nil) {
			return
		}

		// Build command with timeout-aware context
		cmd := exec.CommandContext(execCtx, req.GetCommand()[0], req.GetCommand()[1:]...)

		// Set working directory
		if req.GetWorkDir() != "" {
			cmd.Dir = req.GetWorkDir()
		} else if req.GetWorkspaceDir() != "" {
			cmd.Dir = req.GetWorkspaceDir()
		}

		// Set environment variables
		if len(req.GetEnv()) > 0 {
			cmd.Env = os.Environ()
			for k, v := range req.GetEnv() {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}
		}

		// Set stdin if provided
		if len(req.GetStdin()) > 0 {
			cmd.Stdin = bytes.NewReader(req.GetStdin())
		}

		// Capture output
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Run command
		err := cmd.Run()

		// Send stdout if any
		if stdout.Len() > 0 {
			if !yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Output{
					Output: &sandboxv1.OutputEvent{
						IsStderr: false,
						Data:     stdout.Bytes(),
					},
				},
			}, nil) {
				return
			}
		}

		// Send stderr if any
		if stderr.Len() > 0 {
			if !yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Output{
					Output: &sandboxv1.OutputEvent{
						IsStderr: true,
						Data:     stderr.Bytes(),
					},
				},
			}, nil) {
				return
			}
		}

		// Determine exit code
		exitCode := int32(0)
		if err != nil {
			// Check for context cancellation (timeout or manual cancel)
			if execCtx.Err() == context.DeadlineExceeded {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message:     "execution timed out",
							Code:        "TIMEOUT",
							IsFatal:     true,
							IsRetriable: true,
						},
					},
				}, nil)
				return
			}
			if execCtx.Err() == context.Canceled {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message:     "execution cancelled",
							Code:        "CANCELLED",
							IsFatal:     true,
							IsRetriable: false,
						},
					},
				}, nil)
				return
			}
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = int32(exitErr.ExitCode())
			} else {
				// Non-exit error (e.g., command not found)
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message:     fmt.Sprintf("execution failed: %v", err),
							Code:        "EXEC_FAILED",
							IsFatal:     true,
							IsRetriable: false,
						},
					},
				}, nil)
				return
			}
		}

		// Send completed event
		duration := time.Since(startTime)
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Completed{
				Completed: &sandboxv1.CompletedEvent{
					ExitCode: exitCode,
					Duration: durationpb.New(duration),
				},
			},
		}, nil)
	}
}

// Cleanup is a no-op for the None runtime.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	return nil
}
