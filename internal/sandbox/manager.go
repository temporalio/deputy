package sandbox

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/policy"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Manager coordinates sandbox runtime discovery, policy evaluation, and execution.
// It provides the primary interface for sandboxed execution across Deputy.
type Manager struct {
	registry     RuntimeRegistry
	policyEngine *policy.Engine
	config       *Config
	auditor      *Auditor
	mu           sync.RWMutex
}

// Config configures the sandbox Manager.
type Config struct {
	// DefaultRuntime is the preferred runtime if not specified in the request.
	DefaultRuntime sandboxv1.Runtime

	// FallbackRuntimes are tried in order if the preferred runtime is unavailable.
	FallbackRuntimes []sandboxv1.Runtime

	// DefaultMode is the filesystem mode if not specified.
	DefaultMode sandboxv1.Mode

	// DefaultNetworkMode is the network mode if not specified.
	DefaultNetworkMode sandboxv1.NetworkMode

	// DefaultLimits are applied when limits are not specified in the request.
	DefaultLimits *sandboxv1.ResourceLimits

	// DefaultImage is the container image to use if not specified.
	DefaultImage string

	// PolicyPaths are paths to policy files for sandbox evaluation.
	PolicyPaths []string
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	fallbacks := []sandboxv1.Runtime{sandboxv1.Runtime_RUNTIME_GVISOR, sandboxv1.Runtime_RUNTIME_NONE}
	if runtime.GOOS == "darwin" {
		fallbacks = []sandboxv1.Runtime{sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC, sandboxv1.Runtime_RUNTIME_NONE}
	}

	return &Config{
		DefaultRuntime:     sandboxv1.Runtime_RUNTIME_DOCKER,
		FallbackRuntimes:   fallbacks,
		DefaultMode:        sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		DefaultNetworkMode: sandboxv1.NetworkMode_NETWORK_MODE_NONE,
		DefaultLimits: &sandboxv1.ResourceLimits{
			Memory:  "512m",
			Cpu:     "1.0",
			MaxPids: 100,
		},
		DefaultImage: "alpine:latest",
	}
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithConfig sets the manager configuration.
func WithConfig(cfg *Config) ManagerOption {
	return func(m *Manager) {
		if cfg != nil {
			m.config = cfg
		}
	}
}

// WithPolicyEngine sets the policy engine for sandbox policy evaluation.
func WithPolicyEngine(engine *policy.Engine) ManagerOption {
	return func(m *Manager) {
		m.policyEngine = engine
	}
}

// WithRegistry sets the runtime registry.
func WithRegistry(reg RuntimeRegistry) ManagerOption {
	return func(m *Manager) {
		if reg != nil {
			m.registry = reg
		}
	}
}

// WithAuditor sets the auditor for sandbox audit logging.
func WithAuditor(auditor *Auditor) ManagerOption {
	return func(m *Manager) {
		if auditor != nil {
			m.auditor = auditor
		}
	}
}

// NewManager creates a new sandbox manager.
func NewManager(ctx context.Context, opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		registry: NewRegistry(),
		config:   DefaultConfig(),
		auditor:  NewAuditor(nil), // Uses default slog logger
	}

	for _, opt := range opts {
		opt(m)
	}

	// Set default runtime in registry
	if r, ok := m.registry.(*registry); ok {
		r.SetDefault(m.config.DefaultRuntime)
	}

	return m, nil
}

// RegisterRuntime adds a runtime to the manager.
func (m *Manager) RegisterRuntime(runtime Runtime) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry.Register(runtime)
}

// ListRuntimes returns information about all registered runtimes.
func (m *Manager) ListRuntimes(ctx context.Context, includeUnavailable bool) (*sandboxv1.ListRuntimesResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	runtimes := m.registry.List()
	var infos []*sandboxv1.RuntimeInfo

	for _, rt := range runtimes {
		if lister, ok := rt.(RuntimeInfoLister); ok {
			list, err := lister.RuntimeInfos(ctx, includeUnavailable)
			if err != nil {
				if includeUnavailable {
					infos = append(infos, &sandboxv1.RuntimeInfo{
						Runtime:           rt.Name(),
						Available:         false,
						UnavailableReason: err.Error(),
					})
				}
				continue
			}
			for _, info := range list {
				if info.GetAvailable() || includeUnavailable {
					infos = append(infos, info)
				}
			}
			continue
		}

		info, err := rt.Info(ctx)
		if err != nil {
			if includeUnavailable {
				infos = append(infos, &sandboxv1.RuntimeInfo{
					Runtime:           rt.Name(),
					Available:         false,
					UnavailableReason: err.Error(),
				})
			}
			continue
		}
		if info.GetAvailable() || includeUnavailable {
			infos = append(infos, info)
		}
	}

	defaultRuntime := sandboxv1.Runtime_RUNTIME_UNSPECIFIED
	if def := m.registry.Default(ctx); def != nil {
		defaultRuntime = def.Name()
	}

	return &sandboxv1.ListRuntimesResponse{
		Runtimes:       infos,
		DefaultRuntime: defaultRuntime,
	}, nil
}

// Execute runs a command in a sandbox.
//
// The execution process:
// 1. Validate and normalize the request configuration
// 2. Evaluate sandbox_execution policy entrypoint
// 3. Select an appropriate runtime
// 4. Execute the command and stream events
//
// Context cancellation will terminate the sandbox execution.
func (m *Manager) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		// Use cryptographically secure execution ID
		executionID := GenerateExecutionID("sandbox")
		startTime := time.Now()

		// Check if runtime was explicitly requested before normalization
		explicitlyRequested := req.GetConfig().GetRuntime() != sandboxv1.Runtime_RUNTIME_UNSPECIFIED

		// Normalize configuration with defaults
		cfg := m.normalizeConfig(req.GetConfig())
		req.Config = cfg

		// Select runtime first to log it properly
		selectedRuntime, err := m.selectRuntime(ctx, cfg, explicitlyRequested)
		if err != nil {
			m.auditor.LogExecutionFailed(ctx, executionID, sandboxv1.Runtime_RUNTIME_UNSPECIFIED, err)
			yield(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Error{
					Error: &sandboxv1.ErrorEvent{
						Message: fmt.Sprintf("no suitable runtime: %v", err),
						Code:    "NO_RUNTIME",
						IsFatal: true,
					},
				},
			}, nil)
			return
		}

		runtimeType := selectedRuntime.Name()

		// Audit: Log execution request
		m.auditor.LogExecutionRequested(ctx, executionID, runtimeType, req)

		// Evaluate sandbox_execution policy
		if m.policyEngine != nil {
			if err := m.evaluateExecutionPolicy(ctx, req); err != nil {
				// Audit: Log policy denial
				m.auditor.LogPolicyDenied(ctx, executionID, runtimeType, "sandbox_execution", err.Error())
				// Record OTel metric for policy denial
				otel.RecordSandboxPolicyDenial(ctx, runtimeType.String(), "sandbox_execution")
				yield(&sandboxv1.ExecuteEvent{
					ExecutionId: executionID,
					Timestamp:   timestamppb.Now(),
					Details: &sandboxv1.ExecuteEvent_Error{
						Error: &sandboxv1.ErrorEvent{
							Message: fmt.Sprintf("policy denied execution: %v", err),
							Code:    "POLICY_DENIED",
							IsFatal: true,
						},
					},
				}, nil)
				return
			}
		}

		m.logEnvFiltered(ctx, executionID, runtimeType, req)

		// Audit: Log execution started
		m.auditor.LogExecutionStarted(ctx, executionID, runtimeType)

		slog.Debug("executing sandbox command",
			"runtime", runtimeType.String(),
			"command", req.GetCommand(),
			"workspace", req.GetWorkspaceDir(),
			"mode", cfg.GetMode().String(),
			"network", cfg.GetNetworkMode().String(),
		)

		// Track completion for audit and metrics
		var exitCode int32
		var execErr error

		// Delegate to runtime
		for event, err := range selectedRuntime.Execute(ctx, req) {
			// Capture completion info
			if completed := event.GetCompleted(); completed != nil {
				exitCode = completed.ExitCode
			}
			if errorEvent := event.GetError(); errorEvent != nil && errorEvent.IsFatal {
				execErr = fmt.Errorf("%s: %s", errorEvent.Code, errorEvent.Message)
			}

			if !yield(event, err) {
				return
			}
		}

		// Audit: Log completion or failure
		durationMs := time.Since(startTime).Milliseconds()
		if execErr != nil {
			m.auditor.LogExecutionFailed(ctx, executionID, runtimeType, execErr)
		} else {
			m.auditor.LogExecutionCompleted(ctx, executionID, runtimeType, exitCode, durationMs)
		}

		// Record OTel metrics (host-side observability)
		otel.RecordSandboxExecution(ctx, otel.SandboxExecutionInfo{
			Runtime:            runtimeType.String(),
			PluginName:         cfg.GetPluginName(),
			NetworkMode:        cfg.GetNetworkMode().String(),
			WorkspaceIsolation: cfg.GetWorkspaceIsolation().String(),
			Duration:           float64(durationMs) / 1000.0,
			ExitCode:           exitCode,
			Success:            execErr == nil,
		})
	}
}

// normalizeConfig applies default values to a sandbox configuration.
func (m *Manager) normalizeConfig(cfg *sandboxv1.SandboxConfig) *sandboxv1.SandboxConfig {
	if cfg == nil {
		cfg = &sandboxv1.SandboxConfig{}
	}

	// Create a copy to avoid modifying the original
	normalized := &sandboxv1.SandboxConfig{
		Runtime:                  cfg.Runtime,
		Mode:                     cfg.Mode,
		NetworkMode:              cfg.NetworkMode,
		Image:                    cfg.Image,
		Limits:                   cfg.Limits,
		Mounts:                   cfg.Mounts,
		NetworkAllowlist:         cfg.NetworkAllowlist,
		DropCapabilities:         cfg.DropCapabilities,
		AddCapabilities:          cfg.AddCapabilities,
		SeccompProfile:           cfg.SeccompProfile,
		User:                     cfg.User,
		Group:                    cfg.Group,
		ReadOnlyPaths:            cfg.ReadOnlyPaths,
		HiddenPaths:              cfg.HiddenPaths,
		PluginName:               cfg.PluginName,
		ExtraOptions:             cfg.ExtraOptions,
		ExecAllowlist:            cfg.ExecAllowlist,
		WorkspaceIsolation:       cfg.WorkspaceIsolation,
		FileMask:                 cfg.FileMask,
		ReviewBeforeCommit:       cfg.ReviewBeforeCommit,
		WorkspaceIsolationConfig: cfg.WorkspaceIsolationConfig,
	}

	// Apply defaults
	if normalized.Runtime == sandboxv1.Runtime_RUNTIME_UNSPECIFIED {
		normalized.Runtime = m.config.DefaultRuntime
	}
	if normalized.Mode == sandboxv1.Mode_MODE_UNSPECIFIED {
		normalized.Mode = m.config.DefaultMode
	}
	if normalized.NetworkMode == sandboxv1.NetworkMode_NETWORK_MODE_UNSPECIFIED {
		normalized.NetworkMode = m.config.DefaultNetworkMode
	}
	if normalized.Image == "" {
		normalized.Image = m.config.DefaultImage
	}
	if normalized.Limits == nil {
		normalized.Limits = m.config.DefaultLimits
	}

	return normalized
}

// selectRuntime chooses the best available runtime for the configuration.
// When explicitlyRequested is true, the runtime was specified by the user and
// we should not fall back to alternatives.
func (m *Manager) selectRuntime(ctx context.Context, cfg *sandboxv1.SandboxConfig, explicitlyRequested bool) (Runtime, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	requestedRuntime := cfg.GetRuntime()

	// Try requested runtime first
	if requestedRuntime != sandboxv1.Runtime_RUNTIME_UNSPECIFIED {
		rt := m.registry.Get(requestedRuntime)
		if rt == nil {
			if explicitlyRequested {
				return nil, fmt.Errorf("runtime %s is not registered", requestedRuntime)
			}
		} else if rt.Available(ctx) {
			return rt, nil
		} else if explicitlyRequested {
			// User explicitly requested this runtime but it's not available
			// Provide a more specific error for plugin runtime when a plugin name is specified
			if requestedRuntime == sandboxv1.Runtime_RUNTIME_PLUGIN && cfg.GetPluginName() != "" {
				return nil, fmt.Errorf("plugin %q not found in PATH", cfg.GetPluginName())
			}
			return nil, fmt.Errorf("runtime %s is not available", requestedRuntime)
		}
	}

	// Only try fallback runtimes if not explicitly requested
	if !explicitlyRequested {
		for _, fallback := range m.config.FallbackRuntimes {
			if rt := m.registry.Get(fallback); rt != nil && rt.Available(ctx) {
				slog.Debug("using fallback runtime",
					"requested", requestedRuntime.String(),
					"fallback", fallback.String(),
				)
				return rt, nil
			}
		}
	}

	// Try default only if not explicitly requested
	if !explicitlyRequested {
		if def := m.registry.Default(ctx); def != nil {
			return def, nil
		}
	}

	return nil, fmt.Errorf("no available runtime (requested: %s)", requestedRuntime)
}

// evaluateExecutionPolicy runs the sandbox_execution policy entrypoint.
func (m *Manager) evaluateExecutionPolicy(ctx context.Context, req *sandboxv1.ExecuteRequest) error {
	if m.policyEngine == nil {
		return nil
	}

	// Build policy input as a map since sandbox entrypoints may not be registered yet
	input := map[string]any{
		"command":          req.GetCommand(),
		"workspace_dir":    req.GetWorkspaceDir(),
		"requested_config": req.GetConfig(),
		"context":          req.GetContext(),
	}

	actions, err := m.policyEngine.EvaluateAllMap(ctx, input, "sandbox", "sandbox_execution")
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Check for denials
	for _, action := range actions {
		if policy.ActionTypeIs(action.Type, policy.ActionDeny) {
			return fmt.Errorf("%s: %s", action.Source, action.Reason)
		}
	}

	return nil
}

// Cleanup releases resources for a specific execution.
func (m *Manager) Cleanup(ctx context.Context, runtime sandboxv1.Runtime, executionID string) error {
	m.mu.RLock()
	rt := m.registry.Get(runtime)
	m.mu.RUnlock()

	if rt == nil {
		return fmt.Errorf("runtime %s not found", runtime)
	}

	return rt.Cleanup(ctx, executionID)
}

// Close releases all manager resources.
func (m *Manager) Close() error {
	// Future: cleanup any active executions, close plugin connections, etc.
	return nil
}

// ExecuteSync is a convenience method that runs Execute and collects the result.
// Use Execute directly for streaming output.
func (m *Manager) ExecuteSync(ctx context.Context, req *sandboxv1.ExecuteRequest) *ExecuteResult {
	return CollectResult(m.Execute(ctx, req))
}

// MustRuntime returns a runtime by name, panicking if not found.
// Only use in tests or initialization code.
func (m *Manager) MustRuntime(name sandboxv1.Runtime) Runtime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rt := m.registry.Get(name)
	if rt == nil {
		panic(fmt.Sprintf("runtime %s not found", name))
	}
	return rt
}

// GetRuntime returns a runtime by name.
func (m *Manager) GetRuntime(name sandboxv1.Runtime) Runtime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry.Get(name)
}

// AvailableRuntimes returns all currently available runtimes.
func (m *Manager) AvailableRuntimes(ctx context.Context) []Runtime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry.Available(ctx)
}

func (m *Manager) logEnvFiltered(ctx context.Context, executionID string, runtime sandboxv1.Runtime, req *sandboxv1.ExecuteRequest) {
	if runtime == sandboxv1.Runtime_RUNTIME_NONE {
		return
	}

	env := req.GetEnv()
	if runtime == sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC {
		env = mergeEnv(os.Environ(), env)
	}

	_, removed := FilterEnvVars(env)
	m.auditor.LogEnvFiltered(ctx, executionID, runtime, removed)
}

func mergeEnv(base []string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == "" {
			continue
		}
		merged[key] = value
	}
	for key, value := range extra {
		if key == "" {
			continue
		}
		merged[key] = value
	}
	return merged
}
