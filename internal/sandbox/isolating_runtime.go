package sandbox

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"time"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
	"github.com/temporalio/deputy/internal/sandbox/workspace"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// IsolatingRuntime wraps a Runtime with workspace isolation.
// This is used for host-native runtimes (sandbox-exec, landlock, bwrap) that
// don't natively support workspace isolation modes. Container runtimes like
// Docker handle isolation internally.
//
// The wrapper:
// 1. Sets up workspace isolation before execution (snapshot, overlay, etc.)
// 2. Rewrites the request to use the isolated path
// 3. After execution, emits WorkspaceChangesEvent for review workflow
// 4. Handles teardown based on preserveChanges setting
//
// Security considerations:
// - Isolation is set up before the untrusted command runs
// - Original workspace is never directly accessible to the sandboxed process
// - Changes are captured and can be reviewed before syncing
// - Symlinks in copies are skipped to prevent escape attacks
type IsolatingRuntime struct {
	inner    Runtime
	isolator workspace.Isolator
	cfg      IsolatingRuntimeConfig
}

// IsolatingRuntimeConfig configures the isolating wrapper.
type IsolatingRuntimeConfig struct {
	// Mode determines isolation strategy (snapshot, overlay, etc.)
	Mode sandboxv1.WorkspaceIsolationMode

	// OriginalPath is the host workspace path.
	OriginalPath string

	// ReviewBeforeCommit enables change review workflow.
	ReviewBeforeCommit bool

	// PreserveAfterExecution keeps the isolated workspace for debugging.
	PreserveAfterExecution bool

	// SetupTimeout limits time spent setting up isolation.
	SetupTimeout time.Duration

	// FileMask configuration for hiding sensitive files.
	FileMask *sandboxv1.FileMaskConfig
}

// NewIsolatingRuntime wraps a runtime with workspace isolation.
// Returns nil if isolation is not needed (direct mode or no workspace).
func NewIsolatingRuntime(inner Runtime, cfg IsolatingRuntimeConfig) (*IsolatingRuntime, error) {
	// Don't wrap if no isolation needed (check this first, before validating inputs)
	if cfg.Mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED ||
		cfg.Mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT {
		return nil, nil
	}

	// Now validate required inputs for isolation modes
	if inner == nil {
		return nil, fmt.Errorf("inner runtime is required")
	}

	if cfg.OriginalPath == "" {
		return nil, fmt.Errorf("original path is required for isolation")
	}

	// Set defaults
	if cfg.SetupTimeout == 0 {
		cfg.SetupTimeout = 60 * time.Second
	}

	// Create the underlying isolator
	isolatorCfg := workspace.Config{
		Mode:                   cfg.Mode,
		OriginalPath:           cfg.OriginalPath,
		PreserveAfterExecution: cfg.PreserveAfterExecution || cfg.ReviewBeforeCommit,
		SetupTimeout:           cfg.SetupTimeout,
	}

	isolator, err := workspace.New(isolatorCfg)
	if err != nil {
		return nil, fmt.Errorf("create isolator: %w", err)
	}

	return &IsolatingRuntime{
		inner:    inner,
		isolator: isolator,
		cfg:      cfg,
	}, nil
}

// Name returns the inner runtime's name.
func (r *IsolatingRuntime) Name() sandboxv1.Runtime {
	return r.inner.Name()
}

// Version returns the inner runtime's version.
func (r *IsolatingRuntime) Version(ctx context.Context) string {
	return r.inner.Version(ctx)
}

// Info returns the inner runtime's info.
func (r *IsolatingRuntime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	return r.inner.Info(ctx)
}

// Available returns whether the inner runtime is available.
func (r *IsolatingRuntime) Available(ctx context.Context) bool {
	return r.inner.Available(ctx)
}

// Capabilities returns the inner runtime's capabilities.
func (r *IsolatingRuntime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return r.inner.Capabilities()
}

// Execute runs a command with workspace isolation.
func (r *IsolatingRuntime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := GenerateExecutionID("isolated")

		// Setup isolation first - this happens BEFORE untrusted code runs
		// Use a separate context for setup so we don't cancel the parent
		setupCtx, setupCancel := context.WithTimeout(ctx, r.cfg.SetupTimeout)
		isolatedPath, err := r.isolator.Setup(setupCtx)
		setupCancel()

		if err != nil {
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("failed to setup workspace isolation: %v", err),
						Code:    "ISOLATION_SETUP_ERROR",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		slog.Debug("workspace isolation setup complete",
			"mode", r.cfg.Mode.String(),
			"original", r.cfg.OriginalPath,
			"isolated", isolatedPath,
		)

		// Emit status event
		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Status{
				Status: &sandboxv1.StatusEvent{
					Status:  "workspace_isolated",
					Message: fmt.Sprintf("Workspace isolated using %s mode", r.cfg.Mode.String()),
				},
			},
		}, nil) {
			r.teardown(context.Background(), false)
			return
		}

		// Rewrite request to use isolated path
		// SECURITY: The sandboxed process only sees the isolated copy
		isolatedReq := r.rewriteRequest(req, isolatedPath)

		// Track whether execution completed successfully for teardown
		var execCompleted bool
		var exitCode int32

		// Execute inner runtime against isolated workspace
		for event, err := range r.inner.Execute(ctx, isolatedReq) {
			// Capture completion info
			if completed := event.GetCompleted(); completed != nil {
				execCompleted = true
				exitCode = completed.ExitCode
			}

			// Pass through events (but don't send CompletedEvent yet if review mode)
			if r.cfg.ReviewBeforeCommit && event.GetCompleted() != nil {
				// We'll send it after the WorkspaceChangesEvent
				continue
			}

			if !yield(event, err) {
				r.teardown(context.Background(), false)
				return
			}
		}

		// If review mode is enabled, emit WorkspaceChangesEvent before CompletedEvent
		if r.cfg.ReviewBeforeCommit && execCompleted {
			r.emitWorkspaceChanges(context.Background(), executionID, yield)

			// Now send the CompletedEvent
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Completed{
					Completed: &sandboxv1.CompletedEvent{
						ExitCode: exitCode,
					},
				},
			}, nil)
		}

		// Teardown: preserve if review mode or explicit config
		preserveChanges := r.cfg.ReviewBeforeCommit || r.cfg.PreserveAfterExecution
		r.teardown(context.Background(), preserveChanges)
	}
}

// rewriteRequest creates a copy of the request with the workspace path replaced.
func (r *IsolatingRuntime) rewriteRequest(req *sandboxv1.ExecuteRequest, isolatedPath string) *sandboxv1.ExecuteRequest {
	// Create a shallow copy - we only change the workspace path
	return &sandboxv1.ExecuteRequest{
		Command:      req.Command,
		Config:       req.Config,
		WorkDir:      req.WorkDir,
		Env:          req.Env,
		Stdin:        req.Stdin,
		Timeout:      req.Timeout,
		Context:      req.Context,
		WorkspaceDir: isolatedPath, // SECURITY: Use isolated path
	}
}

// emitWorkspaceChanges sends the WorkspaceChangesEvent for review workflow.
func (r *IsolatingRuntime) emitWorkspaceChanges(ctx context.Context, executionID string, yield func(*sandboxv1.ExecuteEvent, error) bool) {
	changes, err := r.isolator.Changes(ctx)
	if err != nil {
		slog.Warn("failed to get workspace changes for review",
			"error", err,
		)
		return
	}

	if len(changes) == 0 {
		return
	}

	// Convert to proto format
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
				IsolatedPath: r.isolator.IsolatedPath(),
				OriginalPath: r.isolator.OriginalPath(),
			},
		},
	}, nil)

	slog.Debug("emitted workspace changes event",
		"changes", len(protoChanges),
		"isolatedPath", r.isolator.IsolatedPath(),
		"originalPath", r.isolator.OriginalPath(),
	)
}

// teardown cleans up the isolated workspace.
func (r *IsolatingRuntime) teardown(ctx context.Context, preserveChanges bool) {
	// Use a fresh context for teardown (don't let cancellation prevent cleanup)
	teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.isolator.Teardown(teardownCtx, preserveChanges); err != nil {
		slog.Warn("failed to teardown workspace isolation",
			"error", err,
			"preserveChanges", preserveChanges,
		)
	}
}

// Cleanup delegates to the inner runtime.
func (r *IsolatingRuntime) Cleanup(ctx context.Context, executionID string) error {
	return r.inner.Cleanup(ctx, executionID)
}

// Isolator returns the underlying workspace isolator for sync operations.
// This allows callers to sync changes back to the original workspace.
func (r *IsolatingRuntime) Isolator() workspace.Isolator {
	return r.isolator
}

// ShouldWrapWithIsolation returns true if the runtime should be wrapped.
// Container runtimes (Docker, Podman) handle isolation internally.
// Host-native runtimes need the wrapper.
func ShouldWrapWithIsolation(runtime sandboxv1.Runtime) bool {
	switch runtime {
	case sandboxv1.Runtime_RUNTIME_DOCKER,
		sandboxv1.Runtime_RUNTIME_PODMAN,
		sandboxv1.Runtime_RUNTIME_CONTAINERD,
		sandboxv1.Runtime_RUNTIME_GVISOR,
		sandboxv1.Runtime_RUNTIME_FIRECRACKER,
		sandboxv1.Runtime_RUNTIME_APPLE_CONTAINER,
		sandboxv1.Runtime_RUNTIME_PLUGIN:
		// Container runtimes handle isolation internally
		// Plugin runtimes are assumed to handle their own isolation
		return false
	case sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC,
		sandboxv1.Runtime_RUNTIME_BWRAP,
		sandboxv1.Runtime_RUNTIME_NAMESPACES,
		sandboxv1.Runtime_RUNTIME_LANDLOCK:
		// Host-native runtimes need the wrapper
		return true
	case sandboxv1.Runtime_RUNTIME_NONE:
		// No sandboxing - isolation still useful for review workflow
		return true
	default:
		// Unknown runtime - don't wrap (safer default)
		return false
	}
}
