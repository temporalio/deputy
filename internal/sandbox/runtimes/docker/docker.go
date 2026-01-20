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
	"github.com/picatz/deputy/internal/sandbox/workspace"
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

// errorRemediation provides actionable guidance for common error codes.
var errorRemediation = map[string]string{
	"INVALID_REQUEST": "Provide a command to execute. Example: deputy exec -- echo hello",
	"COMMAND_BLOCKED": "The command is blocked by security policy. Use a different command or check the exec allowlist with --exec-allow.",
	"PATH_BLOCKED":    "The workspace path is blocked by security policy. Use a different path or verify the path is within allowed directories.",
	"CLIENT_ERROR": `Docker is not accessible. Common fixes:
  1. Ensure Docker Desktop is running
  2. Check DOCKER_HOST environment variable
  3. Run 'docker info' to verify Docker is working
  4. On Linux, ensure your user is in the docker group: 'sudo usermod -aG docker $USER'`,
	"ISOLATION_SETUP_ERROR": "Failed to set up workspace isolation. Ensure you have write permissions to the temp directory and sufficient disk space.",
	"CONFIG_ERROR": `Invalid container configuration. Common fixes:
  1. Check that the image name is correct
  2. Verify resource limits are valid (e.g., --memory 512m, --cpu 1.0)
  3. Ensure network mode is supported`,
	"IMAGE_PULL_ERROR": `Failed to pull the container image. Common fixes:
  1. Check that the image name is correct (e.g., alpine:latest, not alpine:latestt)
  2. Ensure you have network connectivity
  3. For private registries, run 'docker login' first
  4. Check if the image exists: 'docker pull <image>' manually`,
	"CREATE_ERROR": `Failed to create container. Common fixes:
  1. Check Docker daemon logs: 'docker logs'
  2. Ensure sufficient disk space
  3. Verify the image exists locally or can be pulled
  4. Check resource limits aren't exceeding system capacity`,
	"ATTACH_ERROR": "Failed to attach to container streams. This may indicate Docker daemon issues. Try restarting Docker.",
	"START_ERROR": `Failed to start container. Common fixes:
  1. Check if the command exists in the image
  2. Verify the working directory exists
  3. Check Docker daemon logs for details
  4. Ensure no port conflicts if exposing ports`,
	"WAIT_ERROR":       "Failed to wait for container completion. The container may have terminated abnormally.",
	"CONTAINER_ERROR":  "Container exited with an error. Check the command output above for details.",
	"CANCELLED":        "Operation was cancelled. This typically occurs due to timeout or user interruption.",
	"STREAM_ERROR":     "Failed to stream container output. The container may have terminated unexpectedly.",
}

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
					Error: newErrorEvent("command is required", "INVALID_REQUEST", true, false),
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
					Error: newErrorEvent(err.Error(), "COMMAND_BLOCKED", true, false),
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
					Error: newErrorEvent(err.Error(), "PATH_BLOCKED", true, false),
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
					Error: newErrorEvent(fmt.Sprintf("failed to get Docker client: %v", err), "CLIENT_ERROR", true, true),
				},
			}, nil)
			return
		}

		// Set up workspace isolation if configured
		var isolator *workspace.DockerIsolator
		effectiveWorkspaceDir := req.GetWorkspaceDir()

		cfg := req.GetConfig()
		isolationMode := cfg.GetWorkspaceIsolation()
		if isolationMode != sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED &&
			isolationMode != sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT {

			isolator, err = r.setupWorkspaceIsolation(ctx, req, executionID)
			if err != nil {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: newErrorEvent(fmt.Sprintf("failed to setup workspace isolation: %v", err), "ISOLATION_SETUP_ERROR", true, false),
					},
				}, nil)
				return
			}

			// Setup the isolated workspace
			isolatedPath, err := isolator.Setup(ctx)
			if err != nil {
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: newErrorEvent(fmt.Sprintf("failed to create isolated workspace: %v", err), "ISOLATION_SETUP_ERROR", true, false),
					},
				}, nil)
				return
			}

			effectiveWorkspaceDir = isolatedPath

			// Ensure cleanup on exit
			// If review_before_commit is set, we preserve changes for review
			defer func() {
				preserveChanges := cfg.GetWorkspaceIsolationConfig().GetPreserveAfterExecution() ||
					cfg.GetReviewBeforeCommit()
				if err := isolator.Teardown(context.Background(), preserveChanges); err != nil {
					slog.Warn("failed to teardown workspace isolation",
						"execution_id", executionID,
						"error", err,
					)
				}
			}()

			// Send status event about isolation setup
			if !yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Status{
					Status: &sandboxv1.StatusEvent{
						Status:  "workspace_isolated",
						Message: fmt.Sprintf("Workspace isolated using %s mode", isolationMode.String()),
					},
				},
			}, nil) {
				return
			}
		}

		// Build container configuration with filtered environment and effective workspace
		containerConfig, hostConfig, err := r.buildContainerConfig(req, executionID, filteredEnv, effectiveWorkspaceDir, isolator)
		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: newErrorEvent(fmt.Sprintf("failed to build container config: %v", err), "CONFIG_ERROR", true, false),
				},
			}, nil)
			return
		}

		// Ensure image exists, streaming pull progress if needed
		if err := r.ensureImageWithProgress(ctx, cli, containerConfig.Image, yield, executionID); err != nil {
			code := "IMAGE_PULL_ERROR"
			if errdefs.IsNotFound(err) {
				code = "IMAGE_PULL_ERROR"
			}
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: newErrorEvent(fmt.Sprintf("failed to ensure image %q: %v", containerConfig.Image, err), code, true, code == "IMAGE_PULL_ERROR"),
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
					Error: newErrorEvent(fmt.Sprintf("failed to create container: %v", err), "CREATE_ERROR", true, true),
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
					Error: newErrorEvent(fmt.Sprintf("failed to attach to container: %v", err), "ATTACH_ERROR", true, true),
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
					Error: newErrorEvent(fmt.Sprintf("failed to start container: %v", err), "START_ERROR", true, true),
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
						Error: newErrorEvent(fmt.Sprintf("container wait failed: %v", err), "WAIT_ERROR", true, false),
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
						Error: newErrorEvent(fmt.Sprintf("container error: %s", status.Error.Message), "CONTAINER_ERROR", true, false),
					},
				}, nil)
				return
			}
		case <-ctx.Done():
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: newErrorEvent("context cancelled", "CANCELLED", true, false),
				},
			}, nil)
			return
		}

		// If review mode is enabled and we have an isolator, emit workspace changes before completion
		if isolator != nil && cfg.GetReviewBeforeCommit() {
			changes, changesErr := isolator.Changes(ctx)
			if changesErr != nil {
				slog.Warn("failed to get workspace changes for review", "error", changesErr)
			} else if len(changes) > 0 {
				// Convert workspace.FileChange to proto FileChange
				protoChanges := make([]*sandboxv1.FileChange, 0, len(changes))
				for _, c := range changes {
					protoChanges = append(protoChanges, &sandboxv1.FileChange{
						Path:       c.Path,
						ChangeType: c.Type,
						Size:       c.Size,
						OldPath:    c.OldPath,
					})
				}

				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_WorkspaceChanges{
						WorkspaceChanges: &sandboxv1.WorkspaceChangesEvent{
							Changes:      protoChanges,
							TotalChanges: int32(len(protoChanges)),
							IsolatedPath: isolator.IsolatedPath(),
							OriginalPath: isolator.OriginalPath(),
						},
					},
				}, nil)
			}
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
	return r.ensureImageWithProgress(ctx, cli, image, nil, "")
}

// progressYield is a function type for yielding progress events during image pull.
type progressYield func(event *sandboxv1.ExecuteEvent, err error) bool

// ensureImageWithProgress ensures the image exists, optionally streaming progress events.
// If yield is non-nil and executionID is set, it will emit StatusEvents for pull progress.
func (r *Runtime) ensureImageWithProgress(ctx context.Context, cli *client.Client, image string, yield progressYield, executionID string) error {
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

	// Send initial pull status if streaming
	if yield != nil && executionID != "" {
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Status{
				Status: &sandboxv1.StatusEvent{
					Status:          "image_pull_started",
					Message:         fmt.Sprintf("Pulling image %s", image),
					ProgressPercent: 0,
				},
			},
		}, nil) {
			return ctx.Err()
		}
	}

	pullResp, err := cli.ImagePull(ctx, image, imagetypes.PullOptions{})
	if err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}

	if err := processPullMessages(pullResp, yield, executionID, image); err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}

	// Send completion status if streaming
	if yield != nil && executionID != "" {
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Status{
				Status: &sandboxv1.StatusEvent{
					Status:          "image_pull_complete",
					Message:         fmt.Sprintf("Image %s pulled successfully", image),
					ProgressPercent: 100,
				},
			},
		}, nil) {
			return ctx.Err()
		}
	}

	if _, _, err := cli.ImageInspectWithRaw(ctx, image); err != nil {
		if errdefs.IsNotFound(err) {
			return fmt.Errorf("image %q not found after pull: %w", image, err)
		}
		return fmt.Errorf("inspect image %q after pull: %w", image, err)
	}

	return nil
}

// processPullMessages reads Docker pull messages and optionally streams progress.
func processPullMessages(reader io.ReadCloser, yield progressYield, executionID, image string) error {
	defer reader.Close()

	dec := json.NewDecoder(reader)

	// Track layer progress for overall percentage calculation
	layerProgress := make(map[string]*layerStatus)
	var lastProgressTime time.Time

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

		// Stream progress if enabled
		if yield != nil && executionID != "" && msg.ID != "" {
			// Update layer progress tracking
			if layerProgress[msg.ID] == nil {
				layerProgress[msg.ID] = &layerStatus{}
			}
			layer := layerProgress[msg.ID]
			layer.status = msg.Status

			if msg.Progress != nil {
				layer.current = msg.Progress.Current
				layer.total = msg.Progress.Total
			}

			// Throttle progress updates to avoid overwhelming the consumer
			// Send at most every 100ms, or on significant status changes
			now := time.Now()
			isSignificantChange := msg.Status == "Pull complete" || msg.Status == "Already exists" ||
				msg.Status == "Download complete" || msg.Status == "Extracting"

			if isSignificantChange || now.Sub(lastProgressTime) >= 100*time.Millisecond {
				lastProgressTime = now

				// Calculate overall progress
				percent := calculateOverallProgress(layerProgress)
				statusMsg := formatPullStatus(layerProgress, image)

				if !yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Status{
						Status: &sandboxv1.StatusEvent{
							Status:          "image_pulling",
							Message:         statusMsg,
							ProgressPercent: percent,
						},
					},
				}, nil) {
					return nil // Consumer stopped listening
				}
			}
		}
	}
}

// layerStatus tracks the download/extract status of a single layer.
type layerStatus struct {
	status  string
	current int64
	total   int64
}

// calculateOverallProgress computes a weighted progress percentage across all layers.
func calculateOverallProgress(layers map[string]*layerStatus) int32 {
	if len(layers) == 0 {
		return 0
	}

	var completedLayers, totalLayers int
	var downloadedBytes, totalBytes int64

	for _, layer := range layers {
		totalLayers++
		switch layer.status {
		case "Pull complete", "Already exists":
			completedLayers++
		case "Downloading", "Extracting":
			if layer.total > 0 {
				downloadedBytes += layer.current
				totalBytes += layer.total
			}
		}
	}

	// Weight: 80% for downloads, 20% for completion status
	var percent float64
	if totalBytes > 0 {
		percent = 0.8 * float64(downloadedBytes) / float64(totalBytes) * 100
	}
	if totalLayers > 0 {
		percent += 0.2 * float64(completedLayers) / float64(totalLayers) * 100
	}

	// Clamp to 0-99 (100 is reserved for completion)
	if percent > 99 {
		percent = 99
	}
	return int32(percent)
}

// formatPullStatus creates a human-readable status message for pull progress.
func formatPullStatus(layers map[string]*layerStatus, image string) string {
	var downloading, extracting, complete int
	for _, layer := range layers {
		switch layer.status {
		case "Downloading":
			downloading++
		case "Extracting":
			extracting++
		case "Pull complete", "Already exists":
			complete++
		}
	}

	total := len(layers)
	if extracting > 0 {
		return fmt.Sprintf("Extracting %s: %d/%d layers", image, complete, total)
	}
	if downloading > 0 {
		return fmt.Sprintf("Downloading %s: %d/%d layers", image, complete, total)
	}
	return fmt.Sprintf("Pulling %s: %d/%d layers complete", image, complete, total)
}

// setupWorkspaceIsolation creates a DockerIsolator based on the request configuration.
func (r *Runtime) setupWorkspaceIsolation(ctx context.Context, req *sandboxv1.ExecuteRequest, executionID string) (*workspace.DockerIsolator, error) {
	cfg := req.GetConfig()
	isolationCfg := cfg.GetWorkspaceIsolationConfig()

	// Build file masker from config
	var masker *workspace.FileMasker
	if fileMaskCfg := cfg.GetFileMask(); fileMaskCfg != nil {
		masker = workspace.NewFileMasker(fileMaskCfg)
	}

	// Determine size limit
	sizeLimit := "1g"
	if isolationCfg != nil && isolationCfg.GetOverlaySizeLimit() != "" {
		sizeLimit = isolationCfg.GetOverlaySizeLimit()
	}

	// Determine setup timeout
	setupTimeout := 60 * time.Second
	if isolationCfg != nil && isolationCfg.GetSetupTimeout() != nil {
		setupTimeout = isolationCfg.GetSetupTimeout().AsDuration()
	}

	// Build workspace config
	workspaceCfg := workspace.Config{
		Mode:                   cfg.GetWorkspaceIsolation(),
		OriginalPath:           req.GetWorkspaceDir(),
		OverlaySizeLimit:       sizeLimit,
		SetupTimeout:           setupTimeout,
		PreserveAfterExecution: isolationCfg.GetPreserveAfterExecution(),
	}

	if isolationCfg != nil {
		workspaceCfg.SyncPatterns = isolationCfg.GetSyncPatterns()
		workspaceCfg.ExcludeSyncPatterns = isolationCfg.GetExcludeSyncPatterns()
	}

	return workspace.NewDockerIsolator(workspaceCfg, masker)
}

// buildContainerConfig creates the container configuration from the request.
// The filteredEnv parameter contains environment variables that have been
// sanitized by removing dangerous variables like LD_PRELOAD.
// The effectiveWorkspaceDir is the workspace path to use (may be isolated).
// The isolator is optional and provides Docker-specific mount configuration.
func (r *Runtime) buildContainerConfig(req *sandboxv1.ExecuteRequest, executionID string, filteredEnv map[string]string, effectiveWorkspaceDir string, isolator *workspace.DockerIsolator) (*container.Config, *container.HostConfig, error) {
	cfg := req.GetConfig()

	// Image
	image := strings.TrimSpace(cfg.GetImage())
	if image == "" {
		image = r.DefaultImage
	}

	// Container config
	containerConfig := &container.Config{
		Image:        image,
		Cmd:          req.GetCommand(),
		Tty:          cfg.GetAllocateTty(),
		AttachStdin:  cfg.GetAttachStdin(),
		AttachStdout: true,
		AttachStderr: true,
		OpenStdin:    cfg.GetAttachStdin(),
		StdinOnce:    cfg.GetAttachStdin(), // Close stdin after first disconnect
	}

	// Environment variables (use pre-filtered env for security)
	for k, v := range filteredEnv {
		containerConfig.Env = append(containerConfig.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Working directory
	if effectiveWorkspaceDir != "" {
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
	case sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST:
		// Network allowlist mode: use bridge network with iptables enforcement.
		// We configure the container with an init script that sets up iptables rules
		// to only allow connections to the allowlisted hosts/IPs.
		hostConfig.NetworkMode = network.NetworkBridge

		allowlist := cfg.GetNetworkAllowlist()
		if len(allowlist) > 0 {
			// Add CAP_NET_ADMIN temporarily for iptables setup
			// The init script drops it after configuration
			hostConfig.CapAdd = append(hostConfig.CapAdd, "NET_ADMIN")

			// Build iptables setup commands
			iptablesRules := buildNetworkAllowlistRules(allowlist)

			slog.Debug("network allowlist enforcement enabled",
				"execution_id", executionID,
				"allowlist", allowlist,
				"rules_count", len(iptablesRules),
			)

			// Store rules in environment for the entrypoint wrapper to apply
			// The actual enforcement is done via container init
			containerConfig.Env = append(containerConfig.Env,
				fmt.Sprintf("__DEPUTY_NETWORK_ALLOWLIST=%s", strings.Join(allowlist, ",")),
			)
		} else {
			// Empty allowlist = block all outbound
			slog.Debug("network allowlist mode with empty list blocks all outbound",
				"execution_id", executionID,
			)
			// Use network none for empty allowlist - most secure
			hostConfig.NetworkMode = network.NetworkNone
		}
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
		// Max open files (ulimit -n)
		if limits.MaxFiles > 0 {
			resources.Ulimits = append(resources.Ulimits, &container.Ulimit{
				Name: "nofile",
				Soft: int64(limits.MaxFiles),
				Hard: int64(limits.MaxFiles),
			})
		}
		hostConfig.Resources = resources

		// Disk quota via tmpfs size limit
		// This applies when using ephemeral mode or when the workspace is tmpfs-backed
		if limits.DiskQuota > 0 {
			// Convert bytes to human-readable format for tmpfs options
			diskQuotaStr := formatBytes(limits.DiskQuota)
			if hostConfig.Tmpfs == nil {
				hostConfig.Tmpfs = make(map[string]string)
			}
			// Update /tmp tmpfs with disk quota if present
			if opts, ok := hostConfig.Tmpfs["/tmp"]; ok {
				// Parse existing options and update size
				hostConfig.Tmpfs["/tmp"] = updateTmpfsSize(opts, diskQuotaStr)
			}
		}
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

	// Mounts - use isolator if available, otherwise use standard mounting
	if isolator != nil {
		// Apply isolation-aware mounts via the DockerIsolator
		isolator.ApplyToHostConfig(hostConfig, DefaultWorkspaceMount, cfg.GetMode())
	} else if effectiveWorkspaceDir != "" {
		// Standard workspace mount without isolation
		// Validate workspace path
		if strings.ContainsAny(effectiveWorkspaceDir, "\x00\n\r") {
			return nil, nil, fmt.Errorf("invalid workspace directory path")
		}

		readOnly := true
		mode := cfg.GetMode()
		if mode == sandboxv1.Mode_MODE_WORKSPACE_WRITE || mode == sandboxv1.Mode_MODE_FULL_ACCESS {
			readOnly = false
		}

		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   effectiveWorkspaceDir,
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

// formatBytes converts bytes to a human-readable string for tmpfs size options.
// Returns formats like "64m", "1g", "512k" suitable for tmpfs mount options.
func formatBytes(bytes int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case bytes >= gb && bytes%gb == 0:
		return fmt.Sprintf("%dg", bytes/gb)
	case bytes >= mb && bytes%mb == 0:
		return fmt.Sprintf("%dm", bytes/mb)
	case bytes >= kb && bytes%kb == 0:
		return fmt.Sprintf("%dk", bytes/kb)
	default:
		return fmt.Sprintf("%d", bytes)
	}
}

// updateTmpfsSize updates the size option in a tmpfs options string.
// If size already exists, it's replaced; otherwise it's appended.
func updateTmpfsSize(opts, newSize string) string {
	parts := strings.Split(opts, ",")
	var result []string
	sizeFound := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "size=") {
			result = append(result, "size="+newSize)
			sizeFound = true
		} else if part != "" {
			result = append(result, part)
		}
	}

	if !sizeFound {
		result = append(result, "size="+newSize)
	}

	return strings.Join(result, ",")
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

// buildNetworkAllowlistRules generates iptables rules for the network allowlist.
// Each entry can be:
//   - A hostname (e.g., "api.example.com") - resolved at container start
//   - An IP address (e.g., "192.168.1.1")
//   - A CIDR range (e.g., "10.0.0.0/8")
//   - A host:port combination (e.g., "api.example.com:443")
//
// The rules follow a default-deny policy: all outbound traffic is blocked
// except for explicitly allowed destinations.
func buildNetworkAllowlistRules(allowlist []string) []string {
	if len(allowlist) == 0 {
		return nil
	}

	var rules []string

	// Allow loopback (always needed)
	rules = append(rules, "-A OUTPUT -o lo -j ACCEPT")
	rules = append(rules, "-A INPUT -i lo -j ACCEPT")

	// Allow established connections (for responses)
	rules = append(rules, "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
	rules = append(rules, "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

	// Allow DNS for hostname resolution (UDP and TCP port 53)
	rules = append(rules, "-A OUTPUT -p udp --dport 53 -j ACCEPT")
	rules = append(rules, "-A OUTPUT -p tcp --dport 53 -j ACCEPT")

	// Process each allowlist entry
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Check if entry has a port specification
		host, port, hasPort := strings.Cut(entry, ":")

		// Determine if this is an IP/CIDR or hostname
		// IPs and CIDRs can be used directly; hostnames need resolution
		if isIPOrCIDR(host) {
			if hasPort {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p tcp --dport %s -j ACCEPT", host, port))
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p udp --dport %s -j ACCEPT", host, port))
			} else {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", host))
			}
		} else {
			// Hostname - will be resolved at runtime via init script
			// We mark these with a special comment for the init script to process
			if hasPort {
				rules = append(rules, fmt.Sprintf("# RESOLVE_HOST %s -p tcp --dport %s", host, port))
				rules = append(rules, fmt.Sprintf("# RESOLVE_HOST %s -p udp --dport %s", host, port))
			} else {
				rules = append(rules, fmt.Sprintf("# RESOLVE_HOST %s", host))
			}
		}
	}

	// Default deny for OUTPUT (drop all other outbound traffic)
	rules = append(rules, "-A OUTPUT -j DROP")

	return rules
}

// isIPOrCIDR checks if a string is a valid IP address or CIDR notation.
func isIPOrCIDR(s string) bool {
	// Check for CIDR notation
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		if len(parts) != 2 {
			return false
		}
		s = parts[0]
	}

	// Check if it's a valid IP (v4 or v6)
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		// IPv4
		for _, p := range parts {
			if len(p) == 0 || len(p) > 3 {
				return false
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
		return true
	}

	// IPv6 (contains colons)
	if strings.Contains(s, ":") {
		return true
	}

	return false
}

// newErrorEvent creates an ErrorEvent with remediation guidance.
func newErrorEvent(message, code string, isFatal, isRetriable bool) *sandboxv1.ErrorEvent {
	event := &sandboxv1.ErrorEvent{
		Message:     message,
		Code:        code,
		IsFatal:     isFatal,
		IsRetriable: isRetriable,
	}

	// Add remediation guidance if available
	if remediation, ok := errorRemediation[code]; ok {
		event.Remediation = remediation
	}

	return event
}
