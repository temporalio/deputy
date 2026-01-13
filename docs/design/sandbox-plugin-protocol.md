# Deputy Sandbox Plugin Protocol

## Overview

Deputy supports external sandbox runtimes via plugins. This enables integration with advanced isolation technologies (Firecracker, Lima, custom enterprise sandboxes) without modifying Deputy's core.

The design draws inspiration from:
- [Gemini CLI's proposed sandbox plugin API](https://github.com/google-gemini/gemini-cli/issues/3216)
- Docker's OCI runtime interface
- Kubernetes CRI (Container Runtime Interface)

## Design Goals

1. **Simplicity**: Plugins implement a minimal, well-defined interface
2. **Security**: Plugins run locally only; no network exposure
3. **Composability**: Plugins can wrap other runtimes (Lima wraps containerd)
4. **Discoverability**: Automatic discovery via PATH naming convention
5. **Observability**: Distributed tracing via W3C TraceContext

## Discovery

### Naming Convention

```
deputy-sandbox-<name>
```

Examples:
- `deputy-sandbox-firecracker`
- `deputy-sandbox-lima`
- `deputy-sandbox-wasm`
- `deputy-sandbox-nsjail`

### Discovery Process

```
1. Scan PATH for executables matching deputy-sandbox-*
2. For each executable:
   a. Run: deputy-sandbox-foo --protocol
      → Returns: "1" (protocol version)
   b. Run: deputy-sandbox-foo --spec
      → Returns: Binary procedure specification
   c. Call: GetInfo RPC
      → Returns: RuntimeInfo with capabilities
3. Register plugin in RuntimeRegistry
```

### Configuration Override

```yaml
# .deputy.yaml
plugins:
  sandboxes:
    # Explicit path (skips PATH discovery)
    - name: firecracker
      path: /opt/deputy/plugins/deputy-sandbox-firecracker

    # Additional arguments
    - name: lima
      args: ["--vm-type", "qemu"]

    # Disable auto-discovery
    - name: custom
      path: /usr/local/bin/my-sandbox
      discover: false
```

## Protocol

### Transport

Communication uses [pluginrpc](https://github.com/pluginrpc/pluginrpc) over stdin/stdout:
- Protocol Buffers for serialization
- Streaming support for Execute events
- No network sockets (security boundary)

### Service Definition

```proto
// SandboxRuntimeService is implemented by external sandbox runtime plugins.
service SandboxRuntimeService {
  // GetInfo returns metadata about this sandbox runtime plugin.
  rpc GetInfo(GetRuntimeInfoRequest) returns (GetRuntimeInfoResponse);

  // Execute runs a command in this runtime and streams events.
  rpc Execute(RuntimeExecuteRequest) returns (stream ExecuteEvent);

  // Cleanup releases resources from a previous execution.
  rpc Cleanup(CleanupRequest) returns (CleanupResponse);
}
```

### Message Types

```proto
message GetRuntimeInfoRequest {}

message GetRuntimeInfoResponse {
  // Plugin name (matches deputy-sandbox-<name>)
  string name = 1;

  // Human-readable display name
  string display_name = 2;

  // Plugin version
  string version = 3;

  // Description
  string description = 4;

  // What this runtime can do
  RuntimeCapabilities capabilities = 5;

  // Filesystem modes supported
  repeated Mode supported_modes = 6;
}

message RuntimeExecuteRequest {
  // Command to execute
  repeated string command = 1;

  // Sandbox configuration
  SandboxConfig config = 2;

  // Working directory inside sandbox
  string work_dir = 3;

  // Environment variables (already filtered)
  map<string, string> env = 4;

  // Stdin content
  bytes stdin = 5;

  // Timeout
  google.protobuf.Duration timeout = 6;

  // Workspace directory (absolute path on host)
  string workspace_dir = 7;

  // Execution ID (for cleanup)
  string execution_id = 8;

  // Trace context for distributed tracing
  string trace_context = 9;
}

message CleanupRequest {
  string execution_id = 1;
}

message CleanupResponse {
  bool success = 1;
  string error = 2;
}
```

### Event Streaming

Plugins stream `ExecuteEvent` messages:

```proto
message ExecuteEvent {
  string execution_id = 1;
  google.protobuf.Timestamp timestamp = 2;

  oneof details {
    StartedEvent started = 10;
    OutputEvent output = 11;
    StatusEvent status = 12;
    CompletedEvent completed = 13;
    ErrorEvent error = 14;
  }
}
```

## Plugin SDK (Go)

### Quick Start

```go
package main

import (
    "context"
    "iter"

    sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
    "github.com/picatz/deputy/sdk/sandbox"
)

func main() {
    sandbox.Main(&FirecrackerRuntime{})
}

type FirecrackerRuntime struct {
    // ... configuration
}

func (r *FirecrackerRuntime) Name() string {
    return "firecracker"
}

func (r *FirecrackerRuntime) DisplayName() string {
    return "Firecracker MicroVM"
}

func (r *FirecrackerRuntime) Version() string {
    return "1.0.0"
}

func (r *FirecrackerRuntime) Description() string {
    return "Hardware-isolated sandbox using Firecracker microVMs"
}

func (r *FirecrackerRuntime) Capabilities() *sandboxv1.RuntimeCapabilities {
    return &sandboxv1.RuntimeCapabilities{
        NetworkIsolation:    true,
        FilesystemIsolation: true,
        ResourceLimits:      true,
        Seccomp:             true,
        UserNamespaces:      true,
        Rootless:            false, // Requires KVM
    }
}

func (r *FirecrackerRuntime) SupportedModes() []sandboxv1.Mode {
    return []sandboxv1.Mode{
        sandboxv1.Mode_MODE_READ_ONLY,
        sandboxv1.Mode_MODE_WORKSPACE_WRITE,
        sandboxv1.Mode_MODE_EPHEMERAL,
    }
}

func (r *FirecrackerRuntime) Execute(
    ctx context.Context,
    req *sandboxv1.RuntimeExecuteRequest,
) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        // 1. Create microVM
        // 2. Mount workspace
        // 3. Execute command
        // 4. Stream output
        // 5. Return completion
    }
}

func (r *FirecrackerRuntime) Cleanup(
    ctx context.Context,
    executionID string,
) error {
    // Stop and destroy microVM
    return nil
}
```

### SDK Helpers

```go
package sandbox

// Main is the entry point for sandbox runtime plugins.
func Main(runtime Runtime)

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

// EmitStarted sends a StartedEvent to the yield function.
func EmitStarted(yield YieldFunc, executionID string, runtime sandboxv1.Runtime) bool

// EmitOutput sends an OutputEvent.
func EmitOutput(yield YieldFunc, executionID string, data []byte, isStderr bool) bool

// EmitCompleted sends a CompletedEvent.
func EmitCompleted(yield YieldFunc, executionID string, exitCode int32, duration time.Duration) bool

// EmitError sends an ErrorEvent.
func EmitError(yield YieldFunc, executionID string, err error, isFatal bool) bool

// ExtractTraceContext parses W3C TraceContext from request.
func ExtractTraceContext(traceContext string) (trace.SpanContext, error)
```

## Plugin Examples

### Lima (macOS/Linux VMs)

```go
// deputy-sandbox-lima
type LimaRuntime struct {
    vmName string
    socket string
}

func (r *LimaRuntime) Execute(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        // 1. Ensure Lima VM is running
        if err := r.ensureVM(ctx); err != nil {
            sandbox.EmitError(yield, req.ExecutionId, err, true)
            return
        }

        // 2. Mount workspace into VM
        mountPath, err := r.mountWorkspace(ctx, req.WorkspaceDir)
        if err != nil {
            sandbox.EmitError(yield, req.ExecutionId, err, true)
            return
        }
        defer r.unmountWorkspace(ctx, mountPath)

        // 3. Execute via SSH
        cmd := exec.CommandContext(ctx, "limactl", "shell", r.vmName, "--")
        cmd.Args = append(cmd.Args, req.Command...)
        cmd.Dir = mountPath
        cmd.Env = mapToEnv(req.Env)

        sandbox.EmitStarted(yield, req.ExecutionId, sandboxv1.Runtime_RUNTIME_PLUGIN)

        // ... stream output, wait for completion
    }
}
```

### Nsjail (Linux)

```go
// deputy-sandbox-nsjail
type NsjailRuntime struct {
    configPath string
}

func (r *NsjailRuntime) Execute(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        args := []string{
            "--config", r.configPath,
            "--cwd", req.WorkDir,
            "--bindmount_ro", "/usr",
            "--bindmount_ro", "/lib",
            "--bindmount", fmt.Sprintf("%s:/workspace", req.WorkspaceDir),
        }

        // Apply resource limits
        if limits := req.Config.GetLimits(); limits != nil {
            if limits.Memory != "" {
                args = append(args, "--rlimit_as", limits.Memory)
            }
            if limits.MaxPids > 0 {
                args = append(args, "--max_pids", fmt.Sprint(limits.MaxPids))
            }
        }

        args = append(args, "--")
        args = append(args, req.Command...)

        cmd := exec.CommandContext(ctx, "nsjail", args...)
        // ... execute and stream
    }
}
```

### WebAssembly (Wasmtime)

```go
// deputy-sandbox-wasm
type WasmRuntime struct {
    wasmtime string
}

func (r *WasmRuntime) Capabilities() *sandboxv1.RuntimeCapabilities {
    return &sandboxv1.RuntimeCapabilities{
        NetworkIsolation:    true,  // No network by default
        FilesystemIsolation: true,  // WASI filesystem
        ResourceLimits:      true,  // Fuel-based limits
        Rootless:            true,  // No special privileges
    }
}

func (r *WasmRuntime) Execute(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        // Command[0] is the WASM module path
        wasmModule := req.Command[0]
        wasmArgs := req.Command[1:]

        args := []string{
            "run",
            "--dir", fmt.Sprintf("%s::/workspace", req.WorkspaceDir),
        }

        // Apply WASI capabilities based on config
        if req.Config.GetNetworkMode() != sandboxv1.NetworkMode_NETWORK_MODE_NONE {
            args = append(args, "--wasi", "http")
        }

        args = append(args, wasmModule)
        args = append(args, wasmArgs...)

        cmd := exec.CommandContext(ctx, r.wasmtime, args...)
        // ... execute and stream
    }
}
```

## Distributed Tracing

Plugins receive trace context and should propagate it:

```go
func (r *MyRuntime) Execute(ctx context.Context, req *sandboxv1.RuntimeExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
    return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
        // Extract trace context
        spanCtx, err := sandbox.ExtractTraceContext(req.TraceContext)
        if err == nil {
            ctx = trace.ContextWithSpanContext(ctx, spanCtx)
        }

        // Create child span
        ctx, span := tracer.Start(ctx, "sandbox.execute",
            trace.WithSpanKind(trace.SpanKindInternal),
        )
        defer span.End()

        span.SetAttributes(
            attribute.String("sandbox.runtime", r.Name()),
            attribute.String("sandbox.execution_id", req.ExecutionId),
            attribute.StringSlice("sandbox.command", req.Command),
        )

        // ... execute
    }
}
```

Trace visualization:

```
deputy scan (parent)
├── inventory.extract
│   └── plugin.client.Execute
│       └── [subprocess: nsjail.Execute]
│           └── nsjail.spawn
│               └── process.wait
└── analysis.osv
```

## Security Considerations

### Plugin Trust Model

Plugins run with Deputy's privileges. They are:
- **Trusted**: Installed by user, PATH-discoverable
- **Local-only**: Never exposed over network
- **Audited**: All executions logged

### Input Validation

Deputy validates all requests before sending to plugins:
- Environment variables are filtered
- Paths are validated (no traversal)
- Commands are validated (no dangerous binaries)

Plugins should ALSO validate:
- Config is within declared capabilities
- Resource limits are reasonable
- Workspace path exists and is accessible

### Capability Enforcement

Plugins MUST NOT:
- Execute outside declared capabilities
- Ignore resource limits
- Bypass network restrictions
- Access paths outside workspace

Deputy validates plugin behavior via:
- Capability declaration vs. actual behavior monitoring
- Resource usage tracking
- Network connection auditing (future)

## Testing Plugins

### Protocol Conformance

```bash
# Check protocol version
./deputy-sandbox-myplugin --protocol
# Expected: "1"

# Check procedure spec
./deputy-sandbox-myplugin --spec | xxd
# Expected: Binary protobuf spec
```

### Info RPC

```bash
# Using grpcurl or similar
./deputy-sandbox-myplugin info --format json
{
  "name": "myplugin",
  "displayName": "My Plugin Runtime",
  "version": "1.0.0",
  "capabilities": {
    "networkIsolation": true,
    "filesystemIsolation": true
  },
  "supportedModes": ["MODE_READ_ONLY", "MODE_WORKSPACE_WRITE"]
}
```

### Integration Testing

```go
func TestPluginExecute(t *testing.T) {
    ctx := context.Background()

    // Start plugin
    plugin := plugin.New()
    defer plugin.Close()

    // Create request
    req := &sandboxv1.ExecuteRequest{
        Command:      []string{"echo", "hello"},
        WorkspaceDir: t.TempDir(),
        Config: &sandboxv1.SandboxConfig{
            Runtime:    sandboxv1.Runtime_RUNTIME_PLUGIN,
            PluginName: "myplugin",
            Mode:       sandboxv1.Mode_MODE_WORKSPACE_WRITE,
        },
    }

    // Execute
    var stdout bytes.Buffer
    for event, err := range plugin.Execute(ctx, req) {
        require.NoError(t, err)
        if output := event.GetOutput(); output != nil && !output.IsStderr {
            stdout.Write(output.Data)
        }
    }

    assert.Equal(t, "hello\n", stdout.String())
}
```

### Deputy Integration

```bash
# List available runtimes (should include plugin)
deputy exec --list-runtimes

# Execute using plugin
deputy exec --runtime plugin --plugin myplugin -- echo hello

# With debug logging
DEPUTY_LOG_LEVEL=debug deputy exec --runtime plugin --plugin myplugin -- ls -la
```

## Plugin Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin Lifecycle                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Discovery                                                   │
│     └─ PATH scan for deputy-sandbox-*                           │
│                                                                 │
│  2. Initialization                                              │
│     ├─ --protocol check                                         │
│     ├─ --spec retrieval                                         │
│     └─ GetInfo RPC                                              │
│                                                                 │
│  3. Registration                                                │
│     └─ Add to RuntimeRegistry with capabilities                 │
│                                                                 │
│  4. Selection (per execution)                                   │
│     └─ Manager selects based on request and availability        │
│                                                                 │
│  5. Execution                                                   │
│     ├─ spawn plugin process                                     │
│     ├─ send RuntimeExecuteRequest                               │
│     ├─ stream ExecuteEvent responses                            │
│     └─ wait for completion                                      │
│                                                                 │
│  6. Cleanup                                                     │
│     └─ CleanupRequest for execution_id                          │
│                                                                 │
│  7. Shutdown                                                    │
│     └─ plugin.Close() terminates all plugin processes           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Future Enhancements

### 1. Plugin Manifest

```yaml
# deputy-sandbox-manifest.yaml
name: firecracker
version: 1.0.0
protocol: 1

capabilities:
  network_isolation: true
  filesystem_isolation: true
  resource_limits: true
  hardware_isolation: true  # VM-based

requirements:
  platforms: [linux]
  kernel_version: ">=4.14"
  kvm: true

configuration:
  kernel_path:
    type: string
    required: true
    description: "Path to Linux kernel image"
  rootfs_path:
    type: string
    required: true
    description: "Path to root filesystem image"
```

### 2. Remote Plugin Execution (Enterprise)

For enterprise deployments, plugins could run on dedicated sandbox hosts:

```yaml
# Enterprise configuration
plugins:
  sandboxes:
    - name: firecracker-remote
      endpoint: unix:///var/run/deputy-sandbox.sock
      # OR
      endpoint: https://sandbox.internal:8443
      auth:
        type: mtls
        cert: /etc/deputy/client.crt
        key: /etc/deputy/client.key
```

### 3. Plugin Signing

```bash
# Sign plugin
deputy plugin sign ./deputy-sandbox-myplugin --key signing.key

# Verify before use
deputy plugin verify ./deputy-sandbox-myplugin --keyring /etc/deputy/trusted-keys/

# Enforce in config
plugins:
  require_signature: true
  trusted_keyring: /etc/deputy/trusted-keys/
```
