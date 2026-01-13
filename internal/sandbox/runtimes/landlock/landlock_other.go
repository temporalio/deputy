// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// Package landlock provides a sandbox runtime using Linux Landlock LSM.
// This file provides a stub implementation for non-Linux platforms.
package landlock

import (
	"context"
	"iter"
	"sync"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Runtime implements sandbox.Runtime using Linux Landlock LSM.
// On non-Linux platforms, this runtime is always unavailable.
type Runtime struct {
	mu sync.RWMutex
}

// New creates a new Landlock runtime.
func New() *Runtime {
	return &Runtime{}
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_LANDLOCK.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_LANDLOCK
}

// Info returns metadata about the Landlock runtime.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	return &sandboxv1.RuntimeInfo{
		Runtime:           sandboxv1.Runtime_RUNTIME_LANDLOCK,
		DisplayName:       "Landlock (Linux LSM)",
		Version:           "unavailable",
		Available:         false,
		UnavailableReason: "Landlock is only available on Linux",
		SupportedModes:    []sandboxv1.Mode{},
		Capabilities:      r.Capabilities(),
	}, nil
}

// Available returns false on non-Linux platforms.
func (r *Runtime) Available(ctx context.Context) bool {
	return false
}

// Version returns "unavailable" on non-Linux platforms.
func (r *Runtime) Version(ctx context.Context) string {
	return "unavailable"
}

// Capabilities returns the capabilities (all false for unavailable runtime).
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    false,
		FilesystemIsolation: false,
		ResourceLimits:      false,
		Seccomp:             false,
		Apparmor:            false,
		Selinux:             false,
		UserNamespaces:      false,
		Rootless:            false,
		GpuSupport:          false,
		StreamingOutput:     false,
		InteractiveStdin:    false,
	}
}

// Execute returns an error indicating Landlock is not available.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := sandbox.GenerateExecutionID("landlock")
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: "Landlock runtime is only available on Linux",
					Code:    "RUNTIME_UNAVAILABLE",
					IsFatal: true,
				},
			},
		}, nil)
	}
}

// Cleanup is a no-op for Landlock runtime.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	return nil
}
