package sandbox

import (
	"context"
	"iter"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
)

// Runtime is the interface that sandbox backends implement.
//
// Built-in implementations include Docker, gVisor, and None.
// External plugins can provide additional runtimes by implementing
// the SandboxRuntimeService proto interface.
//
// Implementations must be safe for concurrent use.
type Runtime interface {
	// Name returns the runtime identifier (e.g., RUNTIME_DOCKER).
	Name() sandboxv1.Runtime

	// Info returns metadata about the runtime.
	// Returns availability status, version, and capabilities.
	Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error)

	// Available returns true if the runtime can be used.
	// This checks if required binaries exist and services are running.
	// For example, Docker runtime checks if docker daemon is accessible.
	Available(ctx context.Context) bool

	// Version returns the runtime version string.
	// Returns empty string if version cannot be determined.
	Version(ctx context.Context) string

	// Capabilities returns what this runtime supports.
	// Used for runtime selection and feature negotiation.
	Capabilities() *sandboxv1.RuntimeCapabilities

	// Execute runs a command in the sandbox and streams events.
	//
	// The returned iterator yields events as execution proceeds:
	//   - StartedEvent: Execution has begun
	//   - OutputEvent: stdout/stderr output
	//   - CompletedEvent: Execution finished successfully
	//   - ErrorEvent: An error occurred
	//
	// Callers should iterate until the sequence is exhausted or an error occurs.
	// Context cancellation will terminate the sandbox execution.
	//
	// Example:
	//
	//	for event, err := range runtime.Execute(ctx, req) {
	//	    if err != nil {
	//	        log.Printf("execution error: %v", err)
	//	        break
	//	    }
	//	    // Handle event based on type
	//	}
	Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error]

	// Cleanup releases resources associated with an execution.
	// Should be called after Execute completes to clean up containers, temp files, etc.
	// It is safe to call Cleanup multiple times.
	Cleanup(ctx context.Context, executionID string) error
}

// RuntimeInfoLister allows runtimes to expose multiple RuntimeInfo entries.
// This is useful for plugin-based runtimes that may represent multiple backends.
type RuntimeInfoLister interface {
	RuntimeInfos(ctx context.Context, includeUnavailable bool) ([]*sandboxv1.RuntimeInfo, error)
}

// RuntimeRegistry holds available sandbox runtimes.
// Used by the Manager for runtime discovery and selection.
type RuntimeRegistry interface {
	// Register adds a runtime to the registry.
	Register(runtime Runtime)

	// Get returns a runtime by name, or nil if not found.
	Get(name sandboxv1.Runtime) Runtime

	// List returns all registered runtimes.
	List() []Runtime

	// Available returns runtimes that are currently usable.
	Available(ctx context.Context) []Runtime

	// Default returns the default runtime to use.
	// Returns nil if no runtimes are available.
	Default(ctx context.Context) Runtime
}

// registry is the default RuntimeRegistry implementation.
type registry struct {
	runtimes       map[sandboxv1.Runtime]Runtime
	order          []sandboxv1.Runtime // Registration order for deterministic iteration
	defaultRuntime sandboxv1.Runtime
}

// NewRegistry creates a new runtime registry.
func NewRegistry() RuntimeRegistry {
	return &registry{
		runtimes:       make(map[sandboxv1.Runtime]Runtime),
		order:          make([]sandboxv1.Runtime, 0),
		defaultRuntime: sandboxv1.Runtime_RUNTIME_UNSPECIFIED,
	}
}

// Register adds a runtime to the registry.
func (r *registry) Register(runtime Runtime) {
	name := runtime.Name()
	if _, exists := r.runtimes[name]; !exists {
		r.order = append(r.order, name)
	}
	r.runtimes[name] = runtime
}

// Get returns a runtime by name.
func (r *registry) Get(name sandboxv1.Runtime) Runtime {
	return r.runtimes[name]
}

// List returns all registered runtimes in registration order.
func (r *registry) List() []Runtime {
	result := make([]Runtime, 0, len(r.order))
	for _, name := range r.order {
		if rt, ok := r.runtimes[name]; ok {
			result = append(result, rt)
		}
	}
	return result
}

// Available returns runtimes that are currently usable.
func (r *registry) Available(ctx context.Context) []Runtime {
	var available []Runtime
	for _, name := range r.order {
		rt := r.runtimes[name]
		if rt.Available(ctx) {
			available = append(available, rt)
		}
	}
	return available
}

// Default returns the default runtime.
// Preference order: configured default > Docker > first available.
func (r *registry) Default(ctx context.Context) Runtime {
	// Use explicitly configured default if available
	if r.defaultRuntime != sandboxv1.Runtime_RUNTIME_UNSPECIFIED {
		if rt := r.runtimes[r.defaultRuntime]; rt != nil && rt.Available(ctx) {
			return rt
		}
	}

	// Prefer Docker as it's the most widely available
	if docker := r.runtimes[sandboxv1.Runtime_RUNTIME_DOCKER]; docker != nil && docker.Available(ctx) {
		return docker
	}

	// Fall back to first available
	available := r.Available(ctx)
	if len(available) > 0 {
		return available[0]
	}

	return nil
}

// SetDefault sets the default runtime.
func (r *registry) SetDefault(runtime sandboxv1.Runtime) {
	r.defaultRuntime = runtime
}

// RuntimeOption configures a Runtime implementation.
type RuntimeOption func(any)

// ExecuteResult contains the final result of a sandbox execution.
// This is a convenience type for callers that don't need streaming.
type ExecuteResult struct {
	// ExecutionID is the unique identifier for this execution.
	ExecutionID string

	// ExitCode is the process exit code.
	// 0 indicates success, non-zero indicates failure.
	ExitCode int32

	// Stdout is the captured standard output.
	Stdout []byte

	// Stderr is the captured standard error.
	Stderr []byte

	// Error is set if execution failed.
	Error error

	// Duration is how long the execution took.
	DurationMs int64
}

// CollectResult consumes an Execute iterator and returns the final result.
// This is a convenience function for callers that don't need streaming.
func CollectResult(seq iter.Seq2[*sandboxv1.ExecuteEvent, error]) *ExecuteResult {
	result := &ExecuteResult{}

	for event, err := range seq {
		if err != nil {
			result.Error = err
			return result
		}

		switch details := event.GetDetails().(type) {
		case *sandboxv1.ExecuteEvent_Started:
			result.ExecutionID = event.GetExecutionId()
		case *sandboxv1.ExecuteEvent_Output:
			if details.Output.GetIsStderr() {
				result.Stderr = append(result.Stderr, details.Output.GetData()...)
			} else {
				result.Stdout = append(result.Stdout, details.Output.GetData()...)
			}
		case *sandboxv1.ExecuteEvent_Completed:
			result.ExitCode = details.Completed.GetExitCode()
			if d := details.Completed.GetDuration(); d != nil {
				result.DurationMs = d.AsDuration().Milliseconds()
			}
		case *sandboxv1.ExecuteEvent_Error:
			result.Error = &ExecutionError{
				Message:     details.Error.GetMessage(),
				Code:        details.Error.GetCode(),
				IsFatal:     details.Error.GetIsFatal(),
				IsRetriable: details.Error.GetIsRetriable(),
			}
		}
	}

	return result
}

// ExecutionError represents an error during sandbox execution.
type ExecutionError struct {
	Message     string
	Code        string
	IsFatal     bool
	IsRetriable bool
}

func (e *ExecutionError) Error() string {
	return e.Message
}

// SupportedModes returns the filesystem modes a runtime supports.
// This is a helper for implementations to use in their Info() method.
func SupportedModes(caps *sandboxv1.RuntimeCapabilities) []sandboxv1.Mode {
	modes := []sandboxv1.Mode{sandboxv1.Mode_MODE_READ_ONLY}

	if caps.GetFilesystemIsolation() {
		modes = append(modes, sandboxv1.Mode_MODE_WORKSPACE_WRITE)
	}

	// Full access is always technically supported but may be restricted by policy
	modes = append(modes, sandboxv1.Mode_MODE_FULL_ACCESS)

	if caps.GetNetworkIsolation() {
		modes = append(modes, sandboxv1.Mode_MODE_NETWORK_ISOLATED)
	}

	// Ephemeral mode requires filesystem isolation
	if caps.GetFilesystemIsolation() {
		modes = append(modes, sandboxv1.Mode_MODE_EPHEMERAL)
	}

	return modes
}
