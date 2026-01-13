# Deputy Sandbox Implementation Plan

## Executive Summary

Deputy already has a solid sandbox foundation. This plan outlines enhancements to make it competitive with and superior to other agent sandboxing solutions while maintaining coherence across CLI, API, plugins, and server modes.

## Current State Analysis

### Strengths

1. **Well-designed architecture**: Proto-first design with clear separation
2. **Multiple runtimes**: Docker, gVisor, sandbox-exec, None, Plugin
3. **Security primitives**: Env filtering, path validation, capability management
4. **Policy integration**: CEL-based sandbox policies
5. **Audit logging**: Comprehensive execution audit trail
6. **Streaming events**: Real-time output and status updates

### Gaps to Address

| Gap | Priority | Complexity |
|-----|----------|------------|
| Landlock integration (Linux) | High | Medium |
| Network allowlist enforcement | High | Medium |
| Interactive prompts for dangerous modes | Medium | Low |
| Runtime fallback UX improvements | Medium | Low |
| Apple Container support (future) | Low | High |
| WebAssembly runtime | Low | High |

## Implementation Phases

### Phase 1: Hardening & Polish (2-4 weeks)

#### 1.1 Network Allowlist Enforcement

Currently, network allowlists are passed to runtimes but enforcement varies.

**Task**: Implement consistent network allowlist enforcement across all runtimes.

```go
// internal/sandbox/runtimes/docker/docker.go
func (r *Runtime) applyNetworkConfig(cfg *sandboxv1.SandboxConfig) []string {
    args := []string{}

    switch cfg.GetNetworkMode() {
    case sandboxv1.NetworkMode_NETWORK_MODE_NONE:
        args = append(args, "--network", "none")

    case sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST:
        // Use Docker's built-in iptables or external proxy
        args = append(args, "--network", "deputy-allowlist")
        // Set up iptables rules or use DNS-based allowlist
        for _, host := range cfg.GetNetworkAllowlist() {
            // Implementation: either iptables rules or HTTP proxy
        }
    // ...
    }
    return args
}
```

**Files to modify**:
- [internal/sandbox/runtimes/docker/docker.go](internal/sandbox/runtimes/docker/docker.go)
- [internal/sandbox/runtimes/gvisor/gvisor.go](internal/sandbox/runtimes/gvisor/gvisor.go)

#### 1.2 Interactive Confirmation for Dangerous Modes

**Task**: Add interactive prompts when requesting dangerous capabilities.

```go
// internal/cli/cmd/exec.go
func runExec(ctx context.Context, ...) error {
    // Check for dangerous modes
    if requiresConfirmation(flags) {
        if !confirmDangerousMode(flags, stderr) {
            return fmt.Errorf("operation cancelled")
        }
    }
    // ... proceed
}

func requiresConfirmation(flags *execFlags) bool {
    return flags.mode == "full-access" ||
           flags.network == "host" ||
           // Skip if --yes flag or non-interactive
           (!flags.yes && isatty.IsTerminal(os.Stdin.Fd()))
}
```

**Files to modify**:
- [internal/cli/cmd/exec.go](internal/cli/cmd/exec.go)

#### 1.3 Improved Error Messages

**Task**: Add helpful error messages with remediation suggestions.

```go
// internal/sandbox/errors.go
type RuntimeUnavailableError struct {
    Runtime     sandboxv1.Runtime
    Reason      string
    Suggestions []string
    Available   []sandboxv1.Runtime
}

func (e *RuntimeUnavailableError) Error() string {
    // Format helpful message
}
```

**Files to create/modify**:
- `internal/sandbox/errors.go` (new)
- [internal/cli/cmd/exec.go](internal/cli/cmd/exec.go)

### Phase 2: Landlock Integration (2-3 weeks)

Landlock provides lightweight, unprivileged sandboxing for Linux 5.13+. This is crucial for environments without Docker.

#### 2.1 Landlock Runtime

```go
// internal/sandbox/runtimes/landlock/landlock.go
package landlock

import (
    "context"
    "iter"

    ll "github.com/landlock-lsm/go-landlock/landlock"
    sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

type Runtime struct{}

func New() *Runtime {
    return &Runtime{}
}

func (r *Runtime) Name() sandboxv1.Runtime {
    return sandboxv1.Runtime_RUNTIME_LANDLOCK // Add to proto
}

func (r *Runtime) Available(ctx context.Context) bool {
    // Check kernel version >= 5.13 and Landlock is enabled
    return ll.V5.Available() == nil
}

func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        // 1. Configure Landlock rules based on mode
        var pathRules []ll.PathOpt

        switch req.Config.GetMode() {
        case sandboxv1.Mode_MODE_READ_ONLY:
            pathRules = []ll.PathOpt{
                ll.RODirs(req.WorkspaceDir),
                ll.RODirs("/usr", "/lib", "/lib64"),
            }
        case sandboxv1.Mode_MODE_WORKSPACE_WRITE:
            pathRules = []ll.PathOpt{
                ll.RWDirs(req.WorkspaceDir),
                ll.RODirs("/usr", "/lib", "/lib64"),
            }
        }

        // 2. Apply Landlock restrictions
        if err := ll.V5.BestEffort().RestrictPaths(pathRules...); err != nil {
            // Handle error
        }

        // 3. Execute command (in current process, restrictions apply)
        cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
        // ... stream output
    }
}
```

**Files to create**:
- `internal/sandbox/runtimes/landlock/landlock.go`
- `internal/sandbox/runtimes/landlock/landlock_test.go`

#### 2.2 Proto Updates

```proto
// api/deputy/sandbox/v1/sandbox.proto
enum Runtime {
    // ... existing
    RUNTIME_LANDLOCK = 11;  // Add Landlock
}
```

### Phase 3: Enhanced CLI Experience (1-2 weeks)

#### 3.1 Runtime List Subcommand

```go
// internal/cli/cmd/exec_runtimes.go
func AddExecRuntimesCommand(root *cobra.Command, deps Dependencies) {
    cmd := &cobra.Command{
        Use:   "runtimes",
        Short: "List available sandbox runtimes",
        RunE: func(cmd *cobra.Command, args []string) error {
            return listRuntimes(cmd.Context(), deps, cmd.OutOrStdout())
        },
    }
    root.AddCommand(cmd)
}
```

#### 3.2 Configuration Explain Subcommand

```go
// internal/cli/cmd/exec_explain.go
func AddExecExplainCommand(root *cobra.Command, deps Dependencies) {
    cmd := &cobra.Command{
        Use:   "explain",
        Short: "Explain sandbox configuration",
        RunE: func(cmd *cobra.Command, args []string) error {
            return explainConfig(flags, cmd.OutOrStdout())
        },
    }
    // ... add flags matching exec
    root.AddCommand(cmd)
}
```

#### 3.3 Presets Support

```go
// internal/cli/cmd/exec.go
type execFlags struct {
    // ... existing
    preset string
}

func applyPreset(flags *execFlags) error {
    switch flags.preset {
    case "build":
        if flags.mode == "" { flags.mode = "workspace-write" }
        if flags.network == "" { flags.network = "none" }
        if flags.timeout == 0 { flags.timeout = 10 * time.Minute }
    case "download":
        // ...
    }
    return nil
}
```

### Phase 4: Plugin SDK Enhancement (2-3 weeks)

#### 4.1 Sandbox Plugin SDK

```go
// sdk/sandbox/sdk.go
package sandbox

import (
    "context"
    "iter"

    sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

// Runtime is the interface plugins implement.
type Runtime interface {
    Name() string
    DisplayName() string
    Version() string
    Description() string
    Capabilities() *sandboxv1.RuntimeCapabilities
    SupportedModes() []sandboxv1.Mode
    Execute(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error]
    Cleanup(ctx context.Context, executionID string) error
}

// Main is the entry point for sandbox runtime plugins.
func Main(runtime Runtime) {
    // Handle --protocol, --spec, and RPC commands
}

// Emit helpers for plugins
func EmitStarted(yield YieldFunc, ...) bool
func EmitOutput(yield YieldFunc, ...) bool
func EmitCompleted(yield YieldFunc, ...) bool
func EmitError(yield YieldFunc, ...) bool
```

**Files to create**:
- `sdk/sandbox/sdk.go`
- `sdk/sandbox/helpers.go`
- `sdk/sandbox/trace.go`
- `sdk/sandbox/doc.go`

#### 4.2 Example Plugin

```go
// examples/plugins/sandbox-nsjail/main.go
package main

import "github.com/picatz/deputy/sdk/sandbox"

func main() {
    sandbox.Main(&NsjailRuntime{})
}

type NsjailRuntime struct{}
// ... implement Runtime interface
```

### Phase 5: Advanced Features (3-4 weeks)

#### 5.1 Policy-Based Capability Negotiation

```go
// internal/sandbox/capability_negotiation.go
type CapabilityNegotiator struct {
    policyEngine *policy.Engine
    profiles     map[sandboxv1.ExecutionSource]CapabilityProfile
}

func (n *CapabilityNegotiator) Negotiate(
    ctx context.Context,
    requested *sandboxv1.SandboxConfig,
    source sandboxv1.ExecutionSource,
) (*sandboxv1.SandboxConfig, []ApprovalRequired, error) {
    profile := n.profiles[source]

    // Check each capability against profile
    // Return modified config and list of capabilities needing approval
}
```

#### 5.2 Agent Integration Enhancement

Improve AI agent sandboxing with tighter integration:

```go
// internal/ai/sandbox.go
type AgentSandbox struct {
    manager  *sandbox.Manager
    approver ApprovalFunc
    guardrails *Guardrails
}

func (s *AgentSandbox) ExecuteCommand(ctx context.Context, cmd []string) (*CommandResult, error) {
    // 1. Check guardrails
    if s.guardrails.IsDenied(cmd) {
        return nil, ErrCommandDenied
    }

    // 2. Check if approval needed
    if s.guardrails.RequiresApproval(cmd) {
        if !s.approver(ctx, cmd) {
            return nil, ErrApprovalDenied
        }
    }

    // 3. Execute in sandbox
    req := s.buildRequest(cmd)
    result := s.manager.ExecuteSync(ctx, req)
    return convertResult(result), nil
}
```

## Testing Strategy

### Unit Tests

```go
// internal/sandbox/manager_test.go
func TestManager_Execute(t *testing.T) {
    tests := []struct {
        name    string
        config  *sandboxv1.SandboxConfig
        command []string
        wantErr bool
    }{
        {
            name: "read-only mode blocks writes",
            config: &sandboxv1.SandboxConfig{
                Mode: sandboxv1.Mode_MODE_READ_ONLY,
            },
            command: []string{"touch", "newfile"},
            wantErr: true,
        },
        // ...
    }
}
```

### Integration Tests

```go
// internal/sandbox/integration_test.go
//go:build integration

func TestDockerRuntime_NetworkIsolation(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Test that network=none actually blocks network
    result := executeWithConfig(t, &sandboxv1.SandboxConfig{
        Runtime:     sandboxv1.Runtime_RUNTIME_DOCKER,
        NetworkMode: sandboxv1.NetworkMode_NETWORK_MODE_NONE,
    }, []string{"curl", "-s", "https://example.com"})

    assert.NotEqual(t, 0, result.ExitCode)
}
```

### CLI Tests

```go
// blackbox_test.go
func TestExec_ReadOnlyMode(t *testing.T) {
    output, err := runDeputy(t, "exec", "--mode", "read-only", "--", "touch", "newfile")
    require.Error(t, err)
    assert.Contains(t, output, "read-only")
}
```

## Documentation Updates

### Files to Create/Update

1. **User Guide**: `docs/commands/exec.md`
   - Complete flag reference
   - Examples for common workflows
   - Security recommendations

2. **Architecture**: `docs/reference/sandbox-architecture.md`
   - Runtime comparison
   - Security model
   - Plugin development

3. **AGENTS.md Update**: Add sandbox section
   - Quick reference for sandbox commands
   - Integration with other Deputy features

## Migration Path

### Backward Compatibility

All changes maintain backward compatibility:
- Existing `deputy exec` commands continue to work
- Default behavior unchanged
- New features are opt-in

### Deprecations

None required. sandbox-exec is deprecated by Apple but Deputy can still use it with appropriate warnings.

## Success Metrics

1. **Security**: No escapes in security testing
2. **Performance**: < 500ms overhead for container startup
3. **Usability**: Users can sandbox commands without reading docs
4. **Adoption**: Increased usage of `deputy exec` in CI/CD

## Competitive Analysis

| Feature | Deputy | Gemini CLI | Docker | Claude Code |
|---------|--------|------------|--------|-------------|
| Multiple runtimes | Yes (10+) | Limited | Docker only | Docker |
| Plugin API | Yes | Proposed | No | No |
| Policy engine | CEL | No | No | Limited |
| Network allowlists | Yes | No | Manual | No |
| Approval workflows | Yes | No | No | Yes |
| Audit logging | Yes | Basic | No | No |
| Cross-platform | Yes | Partial | Yes | Yes |

Deputy's advantages:
1. **More runtimes**: Docker, gVisor, Landlock, sandbox-exec, plugins
2. **Policy integration**: CEL policies for fine-grained control
3. **Composable**: Works with CLI, API, plugins, server
4. **Extensible**: Plugin SDK for custom runtimes

## References

### External Projects
- [go-landlock](https://github.com/landlock-lsm/go-landlock)
- [gVisor](https://gvisor.dev/)
- [Firecracker](https://firecracker-microvm.github.io/)
- [Apple Container](https://github.com/apple/container)
- [alcless](https://github.com/AkihiroSuda/alcless)
- [gomodjail](https://github.com/AkihiroSuda/gomodjail)

### Industry Best Practices
- [NVIDIA: Code Execution Risks in Agentic AI](https://developer.nvidia.com/blog/how-code-execution-drives-key-risks-in-agentic-ai-systems/)
- [Agent Sandbox for Kubernetes](https://www.infoq.com/news/2025/12/agent-sandbox-kubernetes/)
- [Claude Code Sandboxing](https://code.claude.com/docs/en/sandboxing)
