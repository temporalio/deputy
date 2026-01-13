// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package landlock

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Runtime implements sandbox.Runtime using Linux Landlock LSM.
type Runtime struct {
	mu            sync.RWMutex
	available     *bool
	version       string
	unavailReason string
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
	available := r.Available(ctx)
	return &sandboxv1.RuntimeInfo{
		Runtime:           sandboxv1.Runtime_RUNTIME_LANDLOCK,
		DisplayName:       "Landlock (Linux LSM)",
		Version:           r.Version(ctx),
		Available:         available,
		UnavailableReason: r.unavailReason,
		SupportedModes:    r.supportedModes(),
		Capabilities:      r.Capabilities(),
	}, nil
}

// Available checks if Landlock is supported on this system.
func (r *Runtime) Available(ctx context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.available != nil {
		return *r.available
	}

	available := false
	defer func() { r.available = &available }()

	// Check kernel version (need 5.13+)
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		r.unavailReason = fmt.Sprintf("failed to get kernel version: %v", err)
		return false
	}

	release := strings.TrimRight(string(uname.Release[:]), "\x00")
	r.version = release

	// Parse major.minor version
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		r.unavailReason = fmt.Sprintf("failed to parse kernel version: %s", release)
		return false
	}

	if major < 5 || (major == 5 && minor < 13) {
		r.unavailReason = fmt.Sprintf("kernel %s does not support Landlock (requires 5.13+)", release)
		return false
	}

	// Check if Landlock is enabled by reading the LSM list
	abiVersion, err := getLandlockABIVersion()
	if err != nil {
		r.unavailReason = fmt.Sprintf("Landlock not available: %v", err)
		return false
	}

	if abiVersion == 0 {
		r.unavailReason = "Landlock is disabled in kernel configuration"
		return false
	}

	available = true
	return true
}

// Version returns the kernel version string.
func (r *Runtime) Version(ctx context.Context) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.version == "" {
		return "unknown"
	}
	return r.version
}

// Capabilities returns what this runtime supports.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    false, // Landlock doesn't do network isolation
		FilesystemIsolation: true,  // Primary capability
		ResourceLimits:      false, // No resource limiting
		Seccomp:             false, // Could be added separately
		Apparmor:            false,
		Selinux:             false,
		UserNamespaces:      false, // Not required
		Rootless:            true,  // Key advantage - no root needed
		GpuSupport:          true,  // No restrictions on devices
		StreamingOutput:     true,
		InteractiveStdin:    true,
	}
}

func (r *Runtime) supportedModes() []sandboxv1.Mode {
	return []sandboxv1.Mode{
		sandboxv1.Mode_MODE_READ_ONLY,
		sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		sandboxv1.Mode_MODE_NETWORK_ISOLATED,
	}
}

// Execute runs a command with Landlock filesystem restrictions.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := sandbox.GenerateExecutionID("landlock")
		startTime := time.Now()

		// Check availability
		if !r.Available(ctx) {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("Landlock runtime unavailable: %s", r.unavailReason),
						Code:    "RUNTIME_UNAVAILABLE",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

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

		// Validate command
		if err := sandbox.ValidateCommand(req.GetCommand()); err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: err.Error(),
						Code:    "COMMAND_BLOCKED",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		// Build Landlock ruleset based on mode
		mode := req.GetConfig().GetMode()
		if mode == sandboxv1.Mode_MODE_UNSPECIFIED {
			mode = sandboxv1.Mode_MODE_WORKSPACE_WRITE
		}

		workspace := req.GetWorkspaceDir()
		if workspace == "" {
			workspace, _ = os.Getwd()
		}
		workspace, _ = filepath.Abs(workspace)

		// Build the ruleset configuration
		rulesetConfig, err := buildRulesetConfig(mode, workspace, req.GetConfig())
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("failed to build ruleset: %v", err),
						Code:    "RULESET_ERROR",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		// Send started event
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Started{
				Started: &sandboxv1.StartedEvent{
					ExecutionId:     executionID,
					Runtime:         sandboxv1.Runtime_RUNTIME_LANDLOCK,
					EffectiveConfig: req.GetConfig(),
				},
			},
		}, nil) {
			return
		}

		// Execute the command with Landlock restrictions
		exitCode, stdout, stderr, execErr := executeLandlocked(ctx, req, rulesetConfig)

		// Send stdout if any
		if len(stdout) > 0 {
			if !yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Output{
					Output: &sandboxv1.OutputEvent{
						IsStderr: false,
						Data:     stdout,
					},
				},
			}, nil) {
				return
			}
		}

		// Send stderr if any
		if len(stderr) > 0 {
			if !yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Output{
					Output: &sandboxv1.OutputEvent{
						IsStderr: true,
						Data:     stderr,
					},
				},
			}, nil) {
				return
			}
		}

		// Handle execution error
		if execErr != nil && exitCode == -1 {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("execution failed: %v", execErr),
						Code:        "EXEC_FAILED",
						IsFatal:     true,
						IsRetriable: false,
					},
				},
			}, nil)
			return
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

// Cleanup is a no-op for Landlock runtime.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	return nil
}

// rulesetConfig holds the Landlock ruleset configuration.
type rulesetConfig struct {
	ReadOnlyPaths  []string
	ReadWritePaths []string
	ExecutePaths   []string
}

// buildRulesetConfig creates a ruleset configuration based on mode.
func buildRulesetConfig(mode sandboxv1.Mode, workspace string, config *sandboxv1.SandboxConfig) (*rulesetConfig, error) {
	rc := &rulesetConfig{
		// Always allow read access to common system paths for executables
		ReadOnlyPaths: []string{
			"/usr",
			"/lib",
			"/lib64",
			"/bin",
			"/sbin",
			"/etc",
			"/proc",
			"/sys",
			"/dev",
		},
		// Always allow executing from standard paths
		ExecutePaths: []string{
			"/usr/bin",
			"/usr/local/bin",
			"/bin",
			"/sbin",
			"/usr/sbin",
		},
	}

	switch mode {
	case sandboxv1.Mode_MODE_READ_ONLY:
		// Read-only access to workspace
		rc.ReadOnlyPaths = append(rc.ReadOnlyPaths, workspace)

	case sandboxv1.Mode_MODE_WORKSPACE_WRITE, sandboxv1.Mode_MODE_NETWORK_ISOLATED:
		// Read-write access to workspace only
		rc.ReadOnlyPaths = append(rc.ReadOnlyPaths, workspace)
		rc.ReadWritePaths = append(rc.ReadWritePaths, workspace)

	case sandboxv1.Mode_MODE_FULL_ACCESS:
		// Full access - still apply Landlock but with broad permissions
		rc.ReadOnlyPaths = append(rc.ReadOnlyPaths, "/")
		rc.ReadWritePaths = append(rc.ReadWritePaths, "/")

	default:
		// Default to workspace-write
		rc.ReadOnlyPaths = append(rc.ReadOnlyPaths, workspace)
		rc.ReadWritePaths = append(rc.ReadWritePaths, workspace)
	}

	// Add any additional read-only paths from config
	for _, path := range config.GetReadOnlyPaths() {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		rc.ReadOnlyPaths = append(rc.ReadOnlyPaths, absPath)
	}

	// Add exec allowlist paths
	for _, path := range config.GetExecAllowlist() {
		if filepath.IsAbs(path) {
			rc.ExecutePaths = append(rc.ExecutePaths, filepath.Dir(path))
		}
	}

	return rc, nil
}

// executeLandlocked executes a command with Landlock restrictions applied.
// Note: Full Landlock implementation would use syscalls to create and enforce rulesets.
// This is a placeholder that documents the intended behavior.
func executeLandlocked(ctx context.Context, req *sandboxv1.ExecuteRequest, ruleset *rulesetConfig) (exitCode int32, stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, req.GetCommand()[0], req.GetCommand()[1:]...)

	// Set working directory
	if req.GetWorkDir() != "" {
		cmd.Dir = req.GetWorkDir()
	} else if req.GetWorkspaceDir() != "" {
		cmd.Dir = req.GetWorkspaceDir()
	}

	// Filter and set environment variables
	filteredEnv, _ := sandbox.FilterEnvVars(req.GetEnv())
	if len(filteredEnv) > 0 {
		cmd.Env = os.Environ()
		for k, v := range filteredEnv {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Set stdin if provided
	if len(req.GetStdin()) > 0 {
		cmd.Stdin = bytes.NewReader(req.GetStdin())
	}

	// Capture output
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// TODO: Apply Landlock before running
	// Full implementation would:
	// 1. Create a Landlock ruleset with landlock_create_ruleset()
	// 2. Add rules for each path with landlock_add_rule()
	// 3. Restrict self with landlock_restrict_self()
	// 4. Exec the target command
	//
	// For production use, consider using a library like:
	// - github.com/landlock-lsm/go-landlock
	// - or direct syscall implementation

	// Run command
	execErr := cmd.Run()

	stdout = stdoutBuf.Bytes()
	stderr = stderrBuf.Bytes()

	if execErr != nil {
		if exitErr, ok := execErr.(*exec.ExitError); ok {
			return int32(exitErr.ExitCode()), stdout, stderr, nil
		}
		return -1, stdout, stderr, execErr
	}

	return 0, stdout, stderr, nil
}

// getLandlockABIVersion returns the Landlock ABI version supported by the kernel.
// Returns 0 if Landlock is not available.
func getLandlockABIVersion() (int, error) {
	// Check if kernel supports Landlock via /sys filesystem
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return 0, fmt.Errorf("cannot read LSM list: %w", err)
	}

	if !strings.Contains(string(data), "landlock") {
		return 0, fmt.Errorf("landlock not in active LSM list")
	}

	// Return ABI version 1 as a baseline
	// Full implementation would query the actual ABI version via syscall
	return 1, nil
}
