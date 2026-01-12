// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

// Package gvisor provides a gVisor sandbox runtime for stronger isolation.
//
// gVisor (runsc) provides application-level sandboxing with a user-space
// kernel that intercepts system calls, providing stronger isolation than
// traditional containers. It's particularly useful for:
//   - Running untrusted code with strong isolation
//   - Multi-tenant environments requiring defense-in-depth
//   - Scenarios where container escapes are a concern
//
// Requirements:
//   - Linux only (gVisor doesn't support macOS/Windows)
//   - runsc binary installed and in PATH
//   - Docker configured to use runsc runtime (for Docker mode)
//
// gVisor can be used in two modes:
//
//  1. Docker mode (default): Uses Docker with --runtime=runsc
//     Requires Docker to be configured with the runsc runtime.
//     Simpler setup, inherits Docker's image management.
//
//  2. Standalone mode: Direct runsc invocation without Docker
//     Lower-level, more control, but requires manual OCI bundle setup.
//     Use WithStandaloneMode() to enable.
//
// Example usage:
//
//	// Docker mode (default)
//	rt := gvisor.New()
//
//	// Standalone mode
//	rt := gvisor.New(gvisor.WithStandaloneMode())
//
//	// Custom runsc path
//	rt := gvisor.New(gvisor.WithRunscPath("/usr/local/bin/runsc"))
package gvisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// logger is the package-level logger for audit events.
	logger = slog.Default()
)

// Runtime implements sandbox.Runtime using gVisor (runsc).
type Runtime struct {
	// runscPath is the path to the runsc binary.
	runscPath string

	// dockerPath is the path to the docker binary.
	dockerPath string

	// dockerRuntime is the Docker runtime name for runsc (default: "runsc").
	dockerRuntime string

	// useDocker indicates whether to use Docker with runsc runtime.
	// If false, uses direct runsc invocation (standalone mode).
	useDocker bool

	// platform is the gVisor platform to use ("ptrace" or "kvm").
	// Only applicable in standalone mode.
	platform string

	// rootfsPath is the path to the root filesystem for standalone mode.
	// If empty, uses a minimal alpine rootfs.
	rootfsPath string

	// networkMode for standalone mode: "host", "none", or "sandbox".
	networkMode string

	// overlayMode for standalone mode: "all:self", "root:self", or "none".
	overlayMode string
}

// OCI Runtime Specification types for config.json generation.
// See: https://github.com/opencontainers/runtime-spec/blob/main/config.md

type ociConfig struct {
	OCIVersion string      `json:"ociVersion"`
	Process    ociProcess  `json:"process"`
	Root       ociRoot     `json:"root"`
	Hostname   string      `json:"hostname"`
	Mounts     []ociMount  `json:"mounts"`
	Linux      *ociLinux   `json:"linux,omitempty"`
}

type ociProcess struct {
	Terminal        bool             `json:"terminal"`
	User            ociUser          `json:"user"`
	Args            []string         `json:"args"`
	Env             []string         `json:"env"`
	Cwd             string           `json:"cwd"`
	Capabilities    *ociCapabilities `json:"capabilities,omitempty"`
	NoNewPrivileges bool             `json:"noNewPrivileges"`
}

type ociUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type ociCapabilities struct {
	Bounding  []string `json:"bounding"`
	Effective []string `json:"effective"`
	Permitted []string `json:"permitted"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type ociLinux struct {
	Namespaces []ociNamespace `json:"namespaces"`
}

type ociNamespace struct {
	Type string `json:"type"`
}

// Option configures a gVisor runtime.
type Option func(*Runtime)

// WithRunscPath sets a custom path to the runsc binary.
func WithRunscPath(path string) Option {
	return func(r *Runtime) {
		r.runscPath = path
	}
}

// WithDockerRuntime sets the Docker runtime name for runsc.
func WithDockerRuntime(name string) Option {
	return func(r *Runtime) {
		r.dockerRuntime = name
	}
}

// WithDockerPath sets the path to the docker binary.
func WithDockerPath(path string) Option {
	return func(r *Runtime) {
		r.dockerPath = path
	}
}

// WithStandaloneMode configures the runtime to use runsc directly without Docker.
// This mode requires manual OCI bundle setup but provides more control.
func WithStandaloneMode() Option {
	return func(r *Runtime) {
		r.useDocker = false
	}
}

// WithPlatform sets the gVisor platform ("ptrace" or "kvm").
// "ptrace" is more compatible, "kvm" is faster but requires /dev/kvm.
// Only applicable in standalone mode.
func WithPlatform(platform string) Option {
	return func(r *Runtime) {
		r.platform = platform
	}
}

// WithRootfsPath sets the root filesystem path for standalone mode.
// The path should contain a valid Linux root filesystem.
func WithRootfsPath(path string) Option {
	return func(r *Runtime) {
		r.rootfsPath = path
	}
}

// WithNetworkModeStandalone sets the network mode for standalone mode.
// Options: "host" (default), "none", "sandbox".
func WithNetworkModeStandalone(mode string) Option {
	return func(r *Runtime) {
		r.networkMode = mode
	}
}

// WithOverlayMode sets the overlay mode for standalone mode.
// Options: "all:self" (full isolation), "root:self" (root only), "none".
func WithOverlayMode(mode string) Option {
	return func(r *Runtime) {
		r.overlayMode = mode
	}
}

// New creates a new gVisor runtime.
func New(opts ...Option) *Runtime {
	r := &Runtime{
		runscPath:     "runsc",
		dockerPath:    "docker",
		dockerRuntime: "runsc",
		useDocker:     true,       // Default to Docker mode for simplicity
		platform:      "",         // Auto-detect (ptrace or kvm)
		networkMode:   "none",     // Default to no network for security
		overlayMode:   "all:self", // Default to full overlay isolation
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_GVISOR.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_GVISOR
}

// Info returns metadata about the gVisor runtime.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	displayName := "gVisor (runsc)"
	if r.useDocker {
		displayName = "gVisor (Docker + runsc)"
	} else {
		displayName = "gVisor (standalone)"
	}

	available := r.Available(ctx)
	info := &sandboxv1.RuntimeInfo{
		Runtime:        sandboxv1.Runtime_RUNTIME_GVISOR,
		DisplayName:    displayName,
		Version:        r.Version(ctx),
		Available:      available,
		SupportedModes: r.supportedModes(),
		Capabilities:   r.Capabilities(),
	}

	if !available {
		if runtime.GOOS != "linux" {
			info.UnavailableReason = "gVisor only supports Linux"
		} else if r.useDocker {
			info.UnavailableReason = "Docker not available or runsc runtime not configured"
		} else {
			info.UnavailableReason = "runsc binary not found in PATH"
		}
	}

	return info, nil
}

// Available checks if gVisor is usable.
// gVisor only works on Linux and requires runsc to be installed.
func (r *Runtime) Available(ctx context.Context) bool {
	// gVisor only supports Linux
	if runtime.GOOS != "linux" {
		return false
	}

	if r.useDocker {
		// Check if Docker is available with runsc runtime
		return r.dockerAvailable(ctx) && r.checkDockerRunsc(ctx)
	}

	// Standalone mode: check if runsc binary exists
	_, err := exec.LookPath(r.runscPath)
	return err == nil
}

// dockerAvailable checks if Docker daemon is accessible.
func (r *Runtime) dockerAvailable(ctx context.Context) bool {
	_, err := exec.LookPath(r.dockerPath)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.dockerPath, "info", "--format", "{{.ServerVersion}}")
	return cmd.Run() == nil
}

// checkDockerRunsc verifies Docker is configured with runsc runtime.
func (r *Runtime) checkDockerRunsc(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Check if runsc runtime is configured in Docker
	// This queries Docker's runtime configuration
	cmd := exec.CommandContext(ctx, r.dockerPath, "info", "--format", "{{json .Runtimes}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check if the runtime appears in the runtimes map
	return strings.Contains(string(output), r.dockerRuntime)
}

// Version returns the runsc version string.
func (r *Runtime) Version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Try to get runsc version directly
	cmd := exec.CommandContext(ctx, r.runscPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse version from output like "runsc version release-20231030.0"
	version := strings.TrimSpace(string(output))
	if idx := strings.Index(version, "runsc version "); idx != -1 {
		return strings.TrimPrefix(version[idx:], "runsc version ")
	}
	return version
}

// Capabilities returns what this runtime supports.
// gVisor provides strong isolation through its user-space kernel.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    true,
		FilesystemIsolation: true,
		ResourceLimits:      true,
		Seccomp:             true,  // gVisor has its own syscall filtering
		Apparmor:            false, // Not applicable with gVisor
		Selinux:             false, // Not applicable with gVisor
		UserNamespaces:      true,
		Rootless:            true, // Supports rootless mode
		GpuSupport:          false, // gVisor has limited GPU support
		StreamingOutput:     true,
		InteractiveStdin:    true,
	}
}

func (r *Runtime) supportedModes() []sandboxv1.Mode {
	return []sandboxv1.Mode{
		sandboxv1.Mode_MODE_READ_ONLY,
		sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		sandboxv1.Mode_MODE_FULL_ACCESS,
		sandboxv1.Mode_MODE_NETWORK_ISOLATED,
		sandboxv1.Mode_MODE_EPHEMERAL,
	}
}

// Execute runs a command in a gVisor sandbox.
// In Docker mode, uses docker with --runtime=runsc.
// In standalone mode, uses runsc directly (not yet fully implemented).
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		// Generate cryptographically secure execution ID
		executionID := sandbox.GenerateExecutionID("gvisor")
		startTime := time.Now()

		// Validate request - command is required
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

		// Validate command for dangerous binaries
		if err := sandbox.ValidateCommand(req.GetCommand()); err != nil {
			logger.WarnContext(ctx, "command blocked by security policy",
				"execution_id", executionID,
				"command", req.GetCommand()[0],
				"reason", err.Error(),
			)
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

		// Validate workspace path
		if err := sandbox.ValidatePath(req.GetWorkspaceDir()); err != nil {
			logger.WarnContext(ctx, "path blocked by security policy",
				"execution_id", executionID,
				"path", req.GetWorkspaceDir(),
				"reason", err.Error(),
			)
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: err.Error(),
						Code:    "PATH_BLOCKED",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		// Filter dangerous environment variables
		filteredEnv, removedEnv := sandbox.FilterEnvVars(req.GetEnv())
		if len(removedEnv) > 0 {
			logger.WarnContext(ctx, "environment variables filtered for security",
				"execution_id", executionID,
				"filtered_vars", removedEnv,
			)
		}

		// Check availability
		if !r.Available(ctx) {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     "gVisor (runsc) is not available on this system",
						Code:        "RUNTIME_UNAVAILABLE",
						IsFatal:     true,
						IsRetriable: false,
					},
				},
			}, nil)
			return
		}

		// Route to appropriate execution mode
		if !r.useDocker {
			r.executeStandalone(ctx, req, executionID, startTime, filteredEnv, yield)
			return
		}

		// Build docker command with runsc runtime using filtered environment
		args := r.buildDockerArgs(req, filteredEnv)

		// Send started event
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Started{
				Started: &sandboxv1.StartedEvent{
					ExecutionId:     executionID,
					Runtime:         sandboxv1.Runtime_RUNTIME_GVISOR,
					EffectiveConfig: req.GetConfig(),
				},
			},
		}, nil) {
			return
		}

		// Execute with Docker + runsc
		cmd := exec.CommandContext(ctx, r.dockerPath, args...)

		// Set working directory if specified
		if req.GetWorkDir() != "" {
			cmd.Dir = req.GetWorkDir()
		}

		// Set stdin if provided
		if len(req.GetStdin()) > 0 {
			cmd.Stdin = bytes.NewReader(req.GetStdin())
		}

		// Create pipes for stdout/stderr
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("failed to create stdout pipe: %v", err),
						Code:    "PIPE_ERROR",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("failed to create stderr pipe: %v", err),
						Code:    "PIPE_ERROR",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		// Start the command
		if err := cmd.Start(); err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to start gVisor container: %v", err),
						Code:        "START_FAILED",
						IsFatal:     true,
						IsRetriable: true,
					},
				},
			}, nil)
			return
		}

		// Stream output in background
		var wg sync.WaitGroup
		outputChan := make(chan *sandboxv1.ExecuteEvent, 100)
		doneChan := make(chan struct{})

		wg.Add(2)
		go r.streamOutput(&wg, stdoutPipe, false, executionID, outputChan)
		go r.streamOutput(&wg, stderrPipe, true, executionID, outputChan)

		// Close output channel when streaming is done
		go func() {
			wg.Wait()
			close(outputChan)
			close(doneChan)
		}()

		// Yield output events as they arrive
		for event := range outputChan {
			if !yield(event, nil) {
				// Consumer stopped, kill the container
				_ = cmd.Process.Kill()
				return
			}
		}

		// Wait for command to finish
		err = cmd.Wait()

		// Determine exit code
		exitCode := int32(0)
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = int32(exitErr.ExitCode())
			} else {
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

// executeStandalone runs a command using runsc directly without Docker.
// This creates an OCI bundle and invokes runsc run.
// The filteredEnv parameter contains environment variables that have been
// sanitized by removing dangerous variables like LD_PRELOAD.
func (r *Runtime) executeStandalone(
	ctx context.Context,
	req *sandboxv1.ExecuteRequest,
	executionID string,
	startTime time.Time,
	filteredEnv map[string]string,
	yield func(*sandboxv1.ExecuteEvent, error) bool,
) {
	// Create a temporary directory for the OCI bundle
	bundleDir, err := os.MkdirTemp("", "gvisor-bundle-")
	if err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to create bundle directory: %v", err),
					Code:    "BUNDLE_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}
	defer os.RemoveAll(bundleDir)

	// Determine rootfs path
	rootfsPath := r.rootfsPath
	if rootfsPath == "" {
		// For standalone mode without a rootfs, we need one to be provided
		// or we could create a minimal one. For now, require it.
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message:     "standalone mode requires a rootfs path; use WithRootfsPath() option",
					Code:        "ROOTFS_REQUIRED",
					IsFatal:     true,
					IsRetriable: false,
				},
			},
		}, nil)
		return
	}

	// Verify rootfs exists
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message:     fmt.Sprintf("rootfs path does not exist: %s", rootfsPath),
					Code:        "ROOTFS_NOT_FOUND",
					IsFatal:     true,
					IsRetriable: false,
				},
			},
		}, nil)
		return
	}

	// Create symlink to rootfs in bundle directory
	bundleRootfs := filepath.Join(bundleDir, "rootfs")
	if err := os.Symlink(rootfsPath, bundleRootfs); err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to symlink rootfs: %v", err),
					Code:    "BUNDLE_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}

	// Generate OCI config with filtered environment
	ociCfg := r.generateOCIConfig(req, filteredEnv)

	// Write config.json
	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Create(configPath)
	if err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to create config.json: %v", err),
					Code:    "CONFIG_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}

	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(ociCfg); err != nil {
		configFile.Close()
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to write config.json: %v", err),
					Code:    "CONFIG_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}
	configFile.Close()

	// Send started event
	if !yield(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Started{
			Started: &sandboxv1.StartedEvent{
				ExecutionId:     executionID,
				Runtime:         sandboxv1.Runtime_RUNTIME_GVISOR,
				EffectiveConfig: req.GetConfig(),
			},
		},
	}, nil) {
		return
	}

	// Build runsc command
	args := r.buildRunscArgs(executionID)
	args = append(args, "run", executionID)

	cmd := exec.CommandContext(ctx, r.runscPath, args...)
	cmd.Dir = bundleDir

	// Set stdin if provided
	if len(req.GetStdin()) > 0 {
		cmd.Stdin = bytes.NewReader(req.GetStdin())
	}

	// Create pipes for stdout/stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to create stdout pipe: %v", err),
					Code:    "PIPE_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message: fmt.Sprintf("failed to create stderr pipe: %v", err),
					Code:    "PIPE_ERROR",
					IsFatal: true,
				},
			},
		}, nil)
		return
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message:     fmt.Sprintf("failed to start runsc: %v", err),
					Code:        "START_FAILED",
					IsFatal:     true,
					IsRetriable: true,
				},
			},
		}, nil)
		return
	}

	// Stream output in background
	var wg sync.WaitGroup
	outputChan := make(chan *sandboxv1.ExecuteEvent, 100)

	wg.Add(2)
	go r.streamOutput(&wg, stdoutPipe, false, executionID, outputChan)
	go r.streamOutput(&wg, stderrPipe, true, executionID, outputChan)

	// Close output channel when streaming is done
	go func() {
		wg.Wait()
		close(outputChan)
	}()

	// Yield output events as they arrive
	for event := range outputChan {
		if !yield(event, nil) {
			// Consumer stopped, kill the process
			_ = cmd.Process.Kill()
			return
		}
	}

	// Wait for command to finish
	err = cmd.Wait()

	// Clean up the sandbox
	cleanupCmd := exec.CommandContext(ctx, r.runscPath, "delete", "-force", executionID)
	_ = cleanupCmd.Run()

	// Determine exit code
	exitCode := int32(0)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = int32(exitErr.ExitCode())
		} else {
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

// generateOCIConfig creates an OCI runtime specification for runsc.
// The filteredEnv parameter contains environment variables that have been
// sanitized by removing dangerous variables like LD_PRELOAD.
func (r *Runtime) generateOCIConfig(req *sandboxv1.ExecuteRequest, filteredEnv map[string]string) *ociConfig {
	config := req.GetConfig()

	// Get current user info
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	// Build environment variables from pre-filtered map
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		fmt.Sprintf("HOME=/home/%s", os.Getenv("USER")),
	}
	for k, v := range filteredEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Determine working directory
	cwd := "/workspace"
	if req.GetWorkDir() != "" {
		cwd = req.GetWorkDir()
	} else if req.GetWorkspaceDir() != "" {
		cwd = req.GetWorkspaceDir()
	}

	// Use safer default capabilities from security module
	// This removes dangerous capabilities like CAP_DAC_OVERRIDE, CAP_SYS_CHROOT,
	// CAP_SETPCAP, and CAP_SETFCAP that could aid container escapes
	caps := sandbox.DefaultCapabilities()

	// Build mounts list
	mounts := []ociMount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},
		},
		{
			Destination: "/dev/shm",
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
		},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
		{
			Destination: "/tmp",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev", "mode=1777"},
		},
	}

	// Add workspace mount if specified
	if req.GetWorkspaceDir() != "" {
		mountOpts := []string{"rbind", "rw"}
		mode := config.GetMode()
		if mode == sandboxv1.Mode_MODE_READ_ONLY {
			mountOpts = []string{"rbind", "ro"}
		}
		mounts = append(mounts, ociMount{
			Destination: req.GetWorkspaceDir(),
			Type:        "bind",
			Source:      req.GetWorkspaceDir(),
			Options:     mountOpts,
		})
	}

	// Add additional mounts from config
	for _, m := range config.GetMounts() {
		opts := []string{"rbind", "rw"}
		if m.GetReadOnly() {
			opts = []string{"rbind", "ro"}
		}
		mounts = append(mounts, ociMount{
			Destination: m.GetTarget(),
			Type:        "bind",
			Source:      m.GetSource(),
			Options:     opts,
		})
	}

	// Get hostname
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "sandbox"
	}

	// Determine if root filesystem should be readonly
	readonly := config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY ||
		config.GetMode() == sandboxv1.Mode_MODE_EPHEMERAL

	return &ociConfig{
		OCIVersion: "1.0.0",
		Process: ociProcess{
			Terminal: false,
			User: ociUser{
				UID: uid,
				GID: gid,
			},
			Args: req.GetCommand(),
			Env:  env,
			Cwd:  cwd,
			Capabilities: &ociCapabilities{
				Bounding:  caps,
				Effective: caps,
				Permitted: caps,
			},
			NoNewPrivileges: false,
		},
		Root: ociRoot{
			Path:     "rootfs",
			Readonly: readonly,
		},
		Hostname: hostname,
		Mounts:   mounts,
		Linux: &ociLinux{
			Namespaces: []ociNamespace{
				{Type: "pid"},
				{Type: "mount"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "user"}, // User namespace for UID/GID isolation
			},
		},
	}
}

// buildRunscArgs constructs the runsc command line arguments.
func (r *Runtime) buildRunscArgs(containerID string) []string {
	args := []string{}

	// Network mode - default to "none" for security
	switch r.networkMode {
	case "none":
		args = append(args, "--network=none")
	case "host":
		args = append(args, "--network=host")
	case "sandbox":
		args = append(args, "--network=sandbox")
	default:
		// Default to no network for security
		args = append(args, "--network=none")
	}

	// Overlay mode for filesystem isolation
	if r.overlayMode != "" && r.overlayMode != "none" {
		args = append(args, "--overlay2="+r.overlayMode)
	}

	// Platform selection
	platform := r.platform
	if platform == "" {
		platform = r.DefaultPlatform()
	}
	if platform != "" {
		args = append(args, "--platform="+platform)
	}

	// File access mode for bind mounts
	args = append(args, "--file-access-mounts=exclusive")

	return args
}

// buildDockerArgs constructs the docker run arguments with runsc runtime.
// The filteredEnv parameter contains environment variables that have been
// sanitized by removing dangerous variables like LD_PRELOAD.
func (r *Runtime) buildDockerArgs(req *sandboxv1.ExecuteRequest, filteredEnv map[string]string) []string {
	args := []string{
		"run",
		"--rm",
		"--runtime=" + r.dockerRuntime,
	}

	config := req.GetConfig()

	// Network mode - gVisor supports network isolation
	switch config.GetNetworkMode() {
	case sandboxv1.NetworkMode_NETWORK_MODE_NONE:
		args = append(args, "--network=none")
	case sandboxv1.NetworkMode_NETWORK_MODE_HOST:
		args = append(args, "--network=host")
	case sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE:
		args = append(args, "--network=bridge")
	default:
		// Default to no network for security
		args = append(args, "--network=none")
	}

	// Resource limits
	if limits := config.GetLimits(); limits != nil {
		if limits.GetMemory() != "" {
			args = append(args, "--memory="+limits.GetMemory())
		}
		if limits.GetCpu() != "" {
			args = append(args, "--cpus="+limits.GetCpu())
		}
		if limits.GetMaxPids() > 0 {
			args = append(args, fmt.Sprintf("--pids-limit=%d", limits.GetMaxPids()))
		}
	}

	// Filesystem mode
	mode := config.GetMode()
	switch mode {
	case sandboxv1.Mode_MODE_READ_ONLY:
		args = append(args, "--read-only")
	case sandboxv1.Mode_MODE_EPHEMERAL:
		// tmpfs overlay for ephemeral mode
		args = append(args, "--read-only")
		args = append(args, "--tmpfs=/tmp:rw,exec,size=256m")
	}

	// Working directory mount
	if req.GetWorkspaceDir() != "" {
		mountOpts := "ro"
		if mode == sandboxv1.Mode_MODE_WORKSPACE_WRITE || mode == sandboxv1.Mode_MODE_FULL_ACCESS {
			mountOpts = "rw"
		}
		args = append(args, "-v", fmt.Sprintf("%s:/workspace:%s", req.GetWorkspaceDir(), mountOpts))
		args = append(args, "-w", "/workspace")
	} else if req.GetWorkDir() != "" {
		args = append(args, "-w", req.GetWorkDir())
	}

	// Additional mounts
	for _, mount := range config.GetMounts() {
		mountOpts := "rw"
		if mount.GetReadOnly() {
			mountOpts = "ro"
		}
		args = append(args, "-v", fmt.Sprintf("%s:%s:%s", mount.GetSource(), mount.GetTarget(), mountOpts))
	}

	// Environment variables (use pre-filtered env for security)
	for k, v := range filteredEnv {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// User (if specified)
	if config.GetUser() != "" {
		args = append(args, "-u", config.GetUser())
	}

	// Image
	image := config.GetImage()
	if image == "" {
		image = "alpine:latest"
	}
	args = append(args, image)

	// Command
	args = append(args, req.GetCommand()...)

	return args
}

// streamOutput reads from a pipe and sends output events.
func (r *Runtime) streamOutput(wg *sync.WaitGroup, pipe io.ReadCloser, isStderr bool, executionID string, out chan<- *sandboxv1.ExecuteEvent) {
	defer wg.Done()
	defer pipe.Close()

	scanner := bufio.NewScanner(pipe)
	// Set a reasonable buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		data := scanner.Bytes()
		// Copy the data since scanner reuses the buffer
		dataCopy := make([]byte, len(data)+1)
		copy(dataCopy, data)
		dataCopy[len(dataCopy)-1] = '\n'

		out <- &sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Output{
				Output: &sandboxv1.OutputEvent{
					IsStderr: isStderr,
					Data:     dataCopy,
				},
			},
		}
	}

	// Handle any remaining data or scanner errors
	if err := scanner.Err(); err != nil && err != io.EOF {
		out <- &sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Error{
				Error: &sandboxv1.ErrorEvent{
					Message:     fmt.Sprintf("output stream error: %v", err),
					Code:        "STREAM_ERROR",
					IsFatal:     false,
					IsRetriable: false,
				},
			},
		}
	}
}

// Cleanup releases resources associated with an execution.
// For gVisor via Docker, the container is already removed by --rm.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	// Docker with --rm already cleans up the container
	// If we tracked container IDs, we could force remove here
	return nil
}

// DefaultPlatform returns the gVisor platform to use.
// Options: "ptrace" (default, most compatible), "kvm" (faster, requires /dev/kvm)
func (r *Runtime) DefaultPlatform() string {
	// Check if KVM is available
	if _, err := os.Stat("/dev/kvm"); err == nil {
		return "kvm"
	}
	return "ptrace"
}
