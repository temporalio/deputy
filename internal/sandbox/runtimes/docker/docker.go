// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

// Package docker provides a Docker container sandbox runtime.
//
// The Docker runtime provides strong isolation via Linux namespaces, cgroups,
// and seccomp filtering. It's the primary runtime for Deputy sandboxing and
// works on Linux, macOS (via Docker Desktop), and Windows (via Docker Desktop).
//
// Features:
//   - Network isolation (none, host, bridge modes)
//   - Filesystem isolation with workspace mounts
//   - Resource limits (memory, CPU, PIDs)
//   - Capability dropping
//   - Seccomp filtering
//   - Read-only root filesystem
//   - OCI runtime selection (runc, runsc/gVisor, etc.)
//
// This implementation uses the Docker SDK (github.com/docker/docker/client)
// for container management, providing type safety, better error handling,
// and native streaming without CLI dependency.
//
// OCI Runtime Support:
// By default, Docker uses the "runc" OCI runtime. You can optionally use
// "runsc" (gVisor) for stronger isolation by specifying WithOCIRuntime("runsc").
// This requires Docker to be configured with the runsc runtime.
//
// Requirements:
//   - Docker daemon running and accessible
//   - For runsc: Docker configured with gVisor runtime
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// logger is the package-level logger for audit events.
	logger = slog.Default()
)

const (
	// DefaultImage is the default container image.
	DefaultImage = "alpine:latest"

	// DefaultWorkspaceMount is where the workspace is mounted inside the container.
	DefaultWorkspaceMount = "/workspace"
)

// Runtime implements sandbox.Runtime using Docker containers via the Docker SDK.
type Runtime struct {
	// DefaultImage is the image to use if none is specified.
	DefaultImage string

	// OCIRuntime is the OCI runtime to use (e.g., "runc", "runsc").
	// If empty, Docker's default runtime is used (typically "runc").
	OCIRuntime string

	// client is the Docker SDK client (lazily initialized).
	client *client.Client

	mu         sync.Mutex
	containers map[string]string // executionID -> containerID
}

// New creates a new Docker runtime.
func New(opts ...Option) *Runtime {
	r := &Runtime{
		DefaultImage: DefaultImage,
		containers:   make(map[string]string),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Option configures a Docker runtime.
type Option func(*Runtime)

// WithDefaultImage sets the default container image.
func WithDefaultImage(image string) Option {
	return func(r *Runtime) {
		if image != "" {
			r.DefaultImage = image
		}
	}
}

// WithOCIRuntime sets the OCI runtime to use (e.g., "runc", "runsc").
// This corresponds to Docker's --runtime flag.
// Common values:
//   - "runc": Default Docker runtime (standard container isolation)
//   - "runsc": gVisor runtime (stronger isolation via user-space kernel)
//   - "crun": Faster alternative to runc
//   - "youki": Rust-based OCI runtime
func WithOCIRuntime(runtime string) Option {
	return func(r *Runtime) {
		r.OCIRuntime = runtime
	}
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_DOCKER.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_DOCKER
}

// getClient returns the Docker client, initializing it if needed.
func (r *Runtime) getClient(ctx context.Context) (*client.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client != nil {
		return r.client, nil
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	r.client = cli
	return cli, nil
}

// Info returns metadata about the Docker runtime.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	version := r.Version(ctx)
	available := r.Available(ctx)

	displayName := "Docker"
	if r.OCIRuntime != "" {
		displayName = fmt.Sprintf("Docker (%s)", r.OCIRuntime)
	}

	info := &sandboxv1.RuntimeInfo{
		Runtime:        sandboxv1.Runtime_RUNTIME_DOCKER,
		DisplayName:    displayName,
		Version:        version,
		Available:      available,
		SupportedModes: sandbox.SupportedModes(r.Capabilities()),
		Capabilities:   r.Capabilities(),
	}

	if !available {
		if r.OCIRuntime != "" && !r.OCIRuntimeAvailable(ctx) {
			info.UnavailableReason = fmt.Sprintf("Docker daemon accessible but OCI runtime %q not configured", r.OCIRuntime)
		} else {
			info.UnavailableReason = "Docker daemon not accessible"
		}
	}

	return info, nil
}

// Available checks if Docker is installed and the daemon is running.
// If an OCI runtime is specified, also checks if that runtime is available.
func (r *Runtime) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cli, err := r.getClient(ctx)
	if err != nil {
		return false
	}

	// Check if daemon is responsive
	_, err = cli.Ping(ctx)
	if err != nil {
		return false
	}

	// If a specific OCI runtime is requested, verify it's available
	if r.OCIRuntime != "" {
		return r.OCIRuntimeAvailable(ctx)
	}

	return true
}

// OCIRuntimeAvailable checks if the specified OCI runtime is configured in Docker.
func (r *Runtime) OCIRuntimeAvailable(ctx context.Context) bool {
	if r.OCIRuntime == "" {
		return true // Default runtime is always available
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cli, err := r.getClient(ctx)
	if err != nil {
		return false
	}

	// Query Docker's runtime configuration
	info, err := cli.Info(ctx)
	if err != nil {
		return false
	}

	// Check if the runtime is in the list of available runtimes
	for name := range info.Runtimes {
		if name == r.OCIRuntime {
			return true
		}
	}

	return false
}

// Version returns the Docker server version.
func (r *Runtime) Version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cli, err := r.getClient(ctx)
	if err != nil {
		return ""
	}

	version, err := cli.ServerVersion(ctx)
	if err != nil {
		return ""
	}

	return version.Version
}

// Capabilities returns what Docker supports.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    true,
		FilesystemIsolation: true,
		ResourceLimits:      true,
		Seccomp:             true,
		Apparmor:            true,  // On Linux with AppArmor enabled
		Selinux:             false, // Requires explicit setup
		UserNamespaces:      true,
		Rootless:            true, // Docker rootless mode
		GpuSupport:          true, // With nvidia-docker
		StreamingOutput:     true,
		InteractiveStdin:    true,
	}
}

// Execute runs a command in a Docker container.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		// Generate cryptographically secure execution ID
		executionID := sandbox.GenerateExecutionID("docker")
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
		filteredEnv, _ := sandbox.FilterEnvVars(req.GetEnv())

		// Get Docker client
		cli, err := r.getClient(ctx)
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to get Docker client: %v", err),
						Code:        "CLIENT_ERROR",
						IsFatal:     true,
						IsRetriable: true,
					},
				},
			}, nil)
			return
		}

		// Build container configuration with filtered environment
		containerConfig, hostConfig, err := r.buildContainerConfig(req, executionID, filteredEnv)
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("failed to build container config: %v", err),
						Code:    "CONFIG_ERROR",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		if err := r.ensureImage(ctx, cli, containerConfig.Image); err != nil {
			code := "IMAGE_PULL_FAILED"
			if errdefs.IsNotFound(err) {
				code = "IMAGE_NOT_FOUND"
			}
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to ensure image %q: %v", containerConfig.Image, err),
						Code:        code,
						IsFatal:     true,
						IsRetriable: code == "IMAGE_PULL_FAILED",
					},
				},
			}, nil)
			return
		}

		slog.Debug("creating docker container",
			"execution_id", executionID,
			"image", containerConfig.Image,
			"cmd", containerConfig.Cmd,
		)

		// Create container
		createResp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, executionID)
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to create container: %v", err),
						Code:        "CREATE_ERROR",
						IsFatal:     true,
						IsRetriable: true,
					},
				},
			}, nil)
			return
		}

		containerID := createResp.ID

		// Track container for cleanup
		r.mu.Lock()
		r.containers[executionID] = containerID
		r.mu.Unlock()

		// Ensure cleanup on exit
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = cli.ContainerRemove(cleanupCtx, containerID, container.RemoveOptions{Force: true})
			r.mu.Lock()
			delete(r.containers, executionID)
			r.mu.Unlock()
		}()

		// Send started event
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Started{
				Started: &sandboxv1.StartedEvent{
					ExecutionId:     executionID,
					Runtime:         sandboxv1.Runtime_RUNTIME_DOCKER,
					ContainerId:     containerID,
					EffectiveConfig: req.GetConfig(),
				},
			},
		}, nil) {
			return
		}

		// Attach to container for output streaming
		attachResp, err := cli.ContainerAttach(ctx, containerID, container.AttachOptions{
			Stream: true,
			Stdout: true,
			Stderr: true,
		})
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to attach to container: %v", err),
						Code:        "ATTACH_ERROR",
						IsFatal:     true,
						IsRetriable: true,
					},
				},
			}, nil)
			return
		}
		defer attachResp.Close()

		// Start container
		if err := cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     fmt.Sprintf("failed to start container: %v", err),
						Code:        "START_ERROR",
						IsFatal:     true,
						IsRetriable: true,
					},
				},
			}, nil)
			return
		}

		// Stream output
		outputCh := make(chan *sandboxv1.ExecuteEvent, 100)
		go r.streamOutput(attachResp.Reader, executionID, outputCh)

		// Yield output events
		for event := range outputCh {
			if !yield(event, nil) {
				// Caller stopped, kill container
				_ = cli.ContainerKill(ctx, containerID, "SIGKILL")
				return
			}
		}

		// Wait for container to finish
		statusCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)

		var exitCode int64
		select {
		case err := <-errCh:
			if err != nil {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message:     fmt.Sprintf("container wait failed: %v", err),
							Code:        "WAIT_ERROR",
							IsFatal:     true,
							IsRetriable: false,
						},
					},
				}, nil)
				return
			}
		case status := <-statusCh:
			exitCode = status.StatusCode
			if status.Error != nil {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message:     fmt.Sprintf("container error: %s", status.Error.Message),
							Code:        "CONTAINER_ERROR",
							IsFatal:     true,
							IsRetriable: false,
						},
					},
				}, nil)
				return
			}
		case <-ctx.Done():
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message:     "context cancelled",
						Code:        "CANCELLED",
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
					ExitCode: int32(exitCode),
					Duration: durationpb.New(duration),
				},
			},
		}, nil)
	}
}

func (r *Runtime) ensureImage(ctx context.Context, cli *client.Client, image string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return fmt.Errorf("image is required")
	}

	if _, _, err := cli.ImageInspectWithRaw(ctx, image); err == nil {
		return nil
	} else if !errdefs.IsNotFound(err) {
		return fmt.Errorf("inspect image %q: %w", image, err)
	}

	slog.Debug("pulling docker image", "image", image)

	pullResp, err := cli.ImagePull(ctx, image, imagetypes.PullOptions{})
	if err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}

	if err := drainPullMessages(pullResp); err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}

	if _, _, err := cli.ImageInspectWithRaw(ctx, image); err != nil {
		if errdefs.IsNotFound(err) {
			return fmt.Errorf("image %q not found after pull: %w", image, err)
		}
		return fmt.Errorf("inspect image %q after pull: %w", image, err)
	}

	return nil
}

func drainPullMessages(reader io.ReadCloser) error {
	defer reader.Close()

	dec := json.NewDecoder(reader)
	for {
		var msg jsonmessage.JSONMessage
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msg.Error != nil {
			return msg.Error
		}
		if msg.ErrorMessage != "" {
			return fmt.Errorf("%s", msg.ErrorMessage)
		}
	}
}

// buildContainerConfig creates the container configuration from the request.
// The filteredEnv parameter contains environment variables that have been
// sanitized by removing dangerous variables like LD_PRELOAD.
func (r *Runtime) buildContainerConfig(req *sandboxv1.ExecuteRequest, executionID string, filteredEnv map[string]string) (*container.Config, *container.HostConfig, error) {
	cfg := req.GetConfig()

	// Image
	image := strings.TrimSpace(cfg.GetImage())
	if image == "" {
		image = r.DefaultImage
	}

	// Container config
	containerConfig := &container.Config{
		Image: image,
		Cmd:   req.GetCommand(),
		Tty:   false,
	}

	// Environment variables (use pre-filtered env for security)
	for k, v := range filteredEnv {
		containerConfig.Env = append(containerConfig.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Working directory
	if req.GetWorkspaceDir() != "" {
		containerConfig.WorkingDir = DefaultWorkspaceMount
	} else if req.GetWorkDir() != "" {
		containerConfig.WorkingDir = req.GetWorkDir()
	}

	// User
	if cfg.GetUser() != "" {
		user := cfg.GetUser()
		if cfg.GetGroup() != "" {
			user += ":" + cfg.GetGroup()
		}
		containerConfig.User = user
	}

	// Host config
	hostConfig := &container.HostConfig{
		AutoRemove: false, // We handle removal ourselves
	}

	// OCI runtime
	if r.OCIRuntime != "" {
		hostConfig.Runtime = r.OCIRuntime
	}

	// Network mode
	switch cfg.GetNetworkMode() {
	case sandboxv1.NetworkMode_NETWORK_MODE_NONE:
		hostConfig.NetworkMode = network.NetworkNone
	case sandboxv1.NetworkMode_NETWORK_MODE_HOST:
		hostConfig.NetworkMode = network.NetworkHost
	case sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE:
		hostConfig.NetworkMode = network.NetworkBridge
	default:
		// Default to no network for security
		hostConfig.NetworkMode = network.NetworkNone
	}

	// Filesystem mode
	switch cfg.GetMode() {
	case sandboxv1.Mode_MODE_READ_ONLY:
		hostConfig.ReadonlyRootfs = true
	case sandboxv1.Mode_MODE_EPHEMERAL:
		hostConfig.ReadonlyRootfs = true
		// Add tmpfs for /tmp
		hostConfig.Tmpfs = map[string]string{
			"/tmp": "rw,noexec,nosuid,size=64m",
		}
	}

	// Resource limits
	if limits := cfg.GetLimits(); limits != nil {
		resources := container.Resources{}
		if limits.Memory != "" {
			if mem, err := parseMemory(limits.Memory); err == nil {
				resources.Memory = mem
			}
		}
		if limits.Cpu != "" {
			if cpu, err := strconv.ParseFloat(limits.Cpu, 64); err == nil {
				resources.NanoCPUs = int64(cpu * 1e9)
			}
		}
		if limits.MaxPids > 0 {
			resources.PidsLimit = ptr(int64(limits.MaxPids))
		}
		hostConfig.Resources = resources
	}

	// Capabilities
	if len(cfg.GetDropCapabilities()) == 0 {
		// Drop all capabilities by default
		hostConfig.CapDrop = []string{"ALL"}
	} else {
		hostConfig.CapDrop = cfg.GetDropCapabilities()
	}
	hostConfig.CapAdd = cfg.GetAddCapabilities()

	// Security options
	if cfg.GetSeccompProfile() != "" {
		hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "seccomp="+cfg.GetSeccompProfile())
	}

	// Mounts
	if workspaceDir := req.GetWorkspaceDir(); workspaceDir != "" {
		// Validate workspace path
		if strings.ContainsAny(workspaceDir, "\x00\n\r") {
			return nil, nil, fmt.Errorf("invalid workspace directory path")
		}

		readOnly := true
		mode := cfg.GetMode()
		if mode == sandboxv1.Mode_MODE_WORKSPACE_WRITE || mode == sandboxv1.Mode_MODE_FULL_ACCESS {
			readOnly = false
		}

		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   workspaceDir,
			Target:   DefaultWorkspaceMount,
			ReadOnly: readOnly,
		})
	}

	// Additional mounts
	for _, m := range cfg.GetMounts() {
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   m.GetSource(),
			Target:   m.GetTarget(),
			ReadOnly: m.GetReadOnly(),
		})
	}

	// Hidden paths (make inaccessible via tmpfs)
	for _, path := range cfg.GetHiddenPaths() {
		if hostConfig.Tmpfs == nil {
			hostConfig.Tmpfs = make(map[string]string)
		}
		hostConfig.Tmpfs[path] = "size=0"
	}

	// Read-only paths
	for _, path := range cfg.GetReadOnlyPaths() {
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   path,
			Target:   path,
			ReadOnly: true,
		})
	}

	return containerConfig, hostConfig, nil
}

// streamOutput reads from the Docker attach response and sends output events.
func (r *Runtime) streamOutput(reader io.Reader, executionID string, out chan<- *sandboxv1.ExecuteEvent) {
	defer close(out)

	// Docker multiplexes stdout/stderr, use stdcopy to demux
	stdoutPr, stdoutPw := io.Pipe()
	stderrPr, stderrPw := io.Pipe()

	go func() {
		defer stdoutPw.Close()
		defer stderrPw.Close()
		// stdcopy.StdCopy handles the multiplexed stream
		_, _ = stdcopy.StdCopy(stdoutPw, stderrPw, reader)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Read stdout
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPr.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				out <- &sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Output{
						Output: &sandboxv1.OutputEvent{
							IsStderr: false,
							Data:     data,
						},
					},
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Read stderr
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stderrPr.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				out <- &sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Output{
						Output: &sandboxv1.OutputEvent{
							IsStderr: true,
							Data:     data,
						},
					},
				}
			}
			if err != nil {
				break
			}
		}
	}()

	wg.Wait()
}

// Cleanup removes a container.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	r.mu.Lock()
	containerID, ok := r.containers[executionID]
	if !ok {
		r.mu.Unlock()
		return nil // Already cleaned up
	}
	delete(r.containers, executionID)
	r.mu.Unlock()

	cli, err := r.getClient(ctx)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
}

// parseMemory parses memory strings like "512m", "2g" to bytes.
func parseMemory(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}

	var multiplier int64 = 1
	if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "kb") {
		multiplier = 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kb"), "k")
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "mb"), "m")
	} else if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "gb"), "g")
	}

	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}

	return val * multiplier, nil
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}

// Expose ExposedPorts helper for container config.
func exposePorts(ports []string) (nat.PortSet, nat.PortMap, error) {
	exposed := nat.PortSet{}
	bindings := nat.PortMap{}

	for _, p := range ports {
		port, err := nat.NewPort("tcp", p)
		if err != nil {
			return nil, nil, err
		}
		exposed[port] = struct{}{}
	}

	return exposed, bindings, nil
}
