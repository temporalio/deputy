# Deputy Sandbox Architecture

## Executive Summary

Deputy's sandbox system provides a unified, composable isolation layer for all execution contexts: plugins, AI agents, remediation commands, and the `deputy exec` CLI. This document describes the architecture from first principles, drawing on modern sandboxing research and best practices.

## Design Principles

### 1. Defense in Depth

Effective sandboxing requires multiple isolation axes:

| Axis | Purpose | Implementation |
|------|---------|----------------|
| **Filesystem** | Prevent unauthorized file access/modification | Mount restrictions, copy-on-write, read-only modes |
| **Network** | Prevent data exfiltration, unauthorized connections | Network namespaces, allowlists, default-deny egress |
| **Process** | Prevent escape, privilege escalation | Namespaces, seccomp, capability dropping |
| **Resource** | Prevent DoS, resource exhaustion | cgroups, ulimits, timeouts |

A sandbox without network isolation can exfiltrate SSH keys. A sandbox without filesystem isolation can backdoor system resources. Deputy implements all four axes.

### 2. Least Privilege

Every execution runs with the minimum permissions required:
- Default: workspace-write + network-none
- Agents: approval workflows for escalation
- Plugins: declared capability requirements
- Server mode: no local filesystem or code execution

### 3. Secure by Default, Escape Hatch Available

```
Restrictive ←──────────────────────→ Permissive
   read-only → workspace-write → full-access
   network-none → allowlist → bridge → host
```

Users must explicitly opt into more permissive modes. Dangerous options require confirmation or special flags.

### 4. Platform-Native When Possible

| Platform | Primary Runtime | Fallback |
|----------|-----------------|----------|
| Linux | Docker/gVisor | Landlock, namespaces |
| macOS | Docker Desktop | sandbox-exec, Apple Container (future) |
| Windows | Docker Desktop | WSL2 |

Use platform-native isolation mechanisms where they provide better security or performance.

### 5. Pluggable and Extensible

External runtimes via `deputy-sandbox-*` plugins enable:
- Hardware-assisted VMs (Firecracker, Lima)
- Custom enterprise sandboxes
- Future platforms (WebAssembly, eBPF-based)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Execution Sources                           │
├─────────────┬─────────────┬──────────────┬────────────┬────────────┤
│ deputy exec │ AI Agents   │ Remediation  │ Plugins    │ Server     │
│ (CLI)       │ (Claude,etc)│ (fix --apply)│ (extractors)│ (multi-tenant)│
└──────┬──────┴──────┬──────┴──────┬───────┴─────┬──────┴──────┬─────┘
       │             │             │             │             │
       └─────────────┴─────────────┴─────────────┴─────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │       Sandbox Manager       │
                    │  • Policy evaluation        │
                    │  • Runtime selection        │
                    │  • Audit logging            │
                    │  • Capability negotiation   │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
┌───────▼───────┐   ┌──────────────▼──────────────┐   ┌───────▼───────┐
│  Built-in     │   │    Container Runtimes       │   │   External    │
│  Runtimes     │   │  • Docker (default)         │   │   Plugins     │
│  • none       │   │  • Podman                   │   │  • Firecracker│
│  • sandbox-   │   │  • containerd               │   │  • Lima       │
│    exec       │   │  • gVisor                   │   │  • sshocker   │
│  • Landlock   │   │  • bubblewrap               │   │  • custom     │
└───────────────┘   └─────────────────────────────┘   └───────────────┘
```

## Runtime Hierarchy

### Tier 1: Maximum Isolation (Recommended for untrusted code)

| Runtime | Mechanism | Overhead | Notes |
|---------|-----------|----------|-------|
| **Firecracker** | Hardware VM (KVM) | ~125ms startup | Best isolation, Linux only |
| **gVisor** | User-space kernel | Medium | Strong isolation, Linux only |
| **Apple Container** | macOS virtualization | TBD | Native on Apple Silicon |

### Tier 2: Container Isolation (Default for most use cases)

| Runtime | Mechanism | Overhead | Notes |
|---------|-----------|----------|-------|
| **Docker** | Linux namespaces + cgroups | Low | Cross-platform via Docker Desktop |
| **Podman** | Rootless containers | Low | No daemon required |
| **containerd** | Direct container runtime | Very low | No Docker daemon |
| **bubblewrap** | Minimal namespaces | Minimal | Flatpak's sandbox |

### Tier 3: Lightweight Isolation (For trusted code or when containers unavailable)

| Runtime | Mechanism | Overhead | Notes |
|---------|-----------|----------|-------|
| **Landlock** | LSM + seccomp | Minimal | Kernel 5.13+, unprivileged |
| **sandbox-exec** | Seatbelt profiles | Minimal | macOS, deprecated but still useful |
| **gomodjail** | Per-module syscall filtering | Minimal | Go-specific supply chain |

### Tier 4: No Isolation (Explicit opt-in only)

| Runtime | Use Case |
|---------|----------|
| **none** | Trusted built-in code, debugging |

## Capability Model

### Filesystem Modes

```proto
enum Mode {
  MODE_READ_ONLY = 1;      // Can read workspace, write nothing
  MODE_WORKSPACE_WRITE = 2; // Read/write in workspace only (default)
  MODE_FULL_ACCESS = 3;     // Unrestricted (dangerous)
  MODE_NETWORK_ISOLATED = 4; // Workspace write + no network
  MODE_EPHEMERAL = 5;       // Copy-on-write, changes discarded
}
```

### Network Modes

```proto
enum NetworkMode {
  NETWORK_MODE_NONE = 1;     // No network access (default)
  NETWORK_MODE_HOST = 2;     // Share host network (dangerous)
  NETWORK_MODE_BRIDGE = 3;   // NAT to host
  NETWORK_MODE_ALLOWLIST = 4; // Only specified hosts/ports
}
```

### Network Allowlists

```yaml
# Policy-based allowlists
network_allowlist:
  - "proxy.golang.org:443"      # Go module proxy
  - "registry.npmjs.org:443"    # npm registry
  - "pypi.org:443"              # PyPI
  - "*.github.com:443"          # GitHub (wildcard)
  - "10.0.0.0/8:*"              # Internal network CIDR
```

### Resource Limits

```proto
message ResourceLimits {
  string memory = 1;           // "512m", "2g"
  string cpu = 2;              // "1.0" = 1 core
  int32 max_pids = 3;          // Process limit
  int32 max_files = 4;         // Open file limit
  int64 disk_quota = 5;        // Bytes
  Duration max_time = 6;       // Execution timeout
}
```

### Capability Dropping

By default, Deputy drops ALL Linux capabilities and adds back only the minimum required:

```go
// Always dropped (dangerous)
var DangerousCapabilities = []string{
    "CAP_SYS_ADMIN",     // Mount, namespace escape
    "CAP_SYS_PTRACE",    // Debug/trace other processes
    "CAP_SYS_MODULE",    // Load kernel modules
    "CAP_SYS_RAWIO",     // Direct I/O
    "CAP_DAC_OVERRIDE",  // Bypass file permissions
}

// Minimal set for most workloads
var MinimalCapabilities = []string{
    "CAP_CHOWN",
    "CAP_FOWNER",
    "CAP_SETGID",
    "CAP_SETUID",
}
```

## Security Boundaries

### Environment Variable Filtering

Sandboxed processes never receive:

```go
var BlockedEnvVars = map[string]bool{
    // Dynamic linker injection
    "LD_PRELOAD": true,
    "DYLD_INSERT_LIBRARIES": true,

    // Language runtime injection
    "PYTHONPATH": true,
    "NODE_OPTIONS": true,
    "JAVA_TOOL_OPTIONS": true,

    // Credential leakage prevention
    "AWS_SECRET_ACCESS_KEY": true,
    "GITHUB_TOKEN": true,
    "ANTHROPIC_API_KEY": true,
}
```

### Path Validation

All paths are validated before mounting:
- No path traversal (`..` resolution)
- Block sensitive system paths (`/etc/passwd`, `/root`, `/proc/1`)
- Symlink resolution to prevent escapes

### Command Validation

Certain binaries are blocked even in containers:
- `nsenter`, `unshare` (namespace manipulation)
- `mount`, `umount` (filesystem manipulation)
- `chroot`, `pivot_root` (root filesystem changes)

## Execution Contexts

### 1. `deputy exec` (CLI)

Direct command execution with user-specified isolation:

```bash
# Read-only exploration
deputy exec --mode read-only -- find . -name "*.go"

# Network-isolated build
deputy exec --mode network-isolated -- go build ./...

# Specific runtime with allowlist
deputy exec --runtime gvisor \
  --network allowlist \
  --network-allow proxy.golang.org:443 \
  -- go mod download
```

### 2. AI Agent Execution

Agents run in sandbox with approval workflows:

```go
type AgentSandbox struct {
    Mode         Mode                 // Default: workspace-write
    NetworkMode  NetworkMode          // Default: none
    ApprovalPolicy *ApprovalPolicy    // Human-in-the-loop
    Guardrails   *Guardrails          // Safety constraints
}

// High-risk operations always require approval
var HighRiskPatterns = []string{
    "sudo *",
    "curl * | *sh",
    "git push --force",
    "git reset --hard",
}
```

### 3. Plugin Execution

Plugins declare required capabilities:

```yaml
# Plugin manifest
name: deputy-extractor-npm
capabilities:
  filesystem: read-only
  network: none
  max_memory: 256m
  timeout: 30s
```

The sandbox manager enforces declared limits.

### 4. Remediation Execution

`deputy fix --apply` runs package manager commands:

```go
// Each ecosystem has known safe commands
var SafeCommands = map[string][]string{
    "go":    {"go", "mod", "get", "build"},
    "npm":   {"npm", "install", "update"},
    "pip":   {"pip", "install", "--upgrade"},
}
```

### 5. Server Mode

Remote servers NEVER execute local code:

```go
func (h *Handler) ExecutePlan(ctx context.Context, req *Request) error {
    if !h.localMode {
        return connect.NewError(
            connect.CodePermissionDenied,
            "ExecutePlan requires local mode",
        )
    }
    // ... proceed with execution
}
```

## Policy Integration

Sandbox execution is governed by CEL policies:

```yaml
policies:
  - name: sandbox-security
    entrypoints: ["sandbox_execution"]
    rules:
      # Block full access for agent execution
      - action: deny
        when: |
          context.source == "EXECUTION_SOURCE_AGENT" &&
          config.mode == "MODE_FULL_ACCESS"
        reason: "Agents cannot use full filesystem access"

      # Require approval for network access
      - action: require_approval
        when: |
          config.network_mode != "NETWORK_MODE_NONE" &&
          context.source == "EXECUTION_SOURCE_AGENT"
        reason: "Network access requires approval"

      # Limit container images
      - action: deny
        when: |
          config.image != "" &&
          !config.image.matches("^(alpine|debian|ubuntu):")
        reason: "Only approved base images allowed"
```

## Audit Logging

All sandbox executions are logged:

```go
type AuditEvent struct {
    ExecutionID    string
    Runtime        Runtime
    Command        string  // Executable only, not args
    Mode           Mode
    NetworkMode    NetworkMode
    User           string
    ExitCode       int32
    DurationMs     int64
    FilteredEnvVars []string  // Which env vars were blocked
    PolicyDenials   []string  // Any policy violations
}
```

Sensitive data (command arguments, environment values) are NOT logged.

## Plugin Runtime Protocol

External runtimes implement `SandboxRuntimeService`:

```proto
service SandboxRuntimeService {
  rpc GetInfo(GetRuntimeInfoRequest) returns (GetRuntimeInfoResponse);
  rpc Execute(RuntimeExecuteRequest) returns (stream ExecuteEvent);
  rpc Cleanup(CleanupRequest) returns (CleanupResponse);
}
```

Discovery:
1. Scan PATH for `deputy-sandbox-*` executables
2. Validate plugin protocol version
3. Query capabilities
4. Register in runtime registry

Communication:
- Local: Unix sockets with ConnectRPC
- Remote: Never (plugins are local-only)

## Recent Enhancements

### Landlock Runtime (Implemented)

Linux 5.13+ provides Landlock LSM for lightweight, unprivileged filesystem sandboxing:

```bash
# Use Landlock runtime (Linux only)
deputy exec --runtime landlock --mode read-only -- cat /etc/passwd

# Landlock with workspace write
deputy exec --runtime landlock --mode workspace-write -- npm install
```

The Landlock runtime (`internal/sandbox/runtimes/landlock/`) provides:
- No root required
- Kernel-native (no external dependencies)
- Process-wide enforcement
- Stackable with other LSMs
- Automatic kernel version detection (5.13+ required)

### Command Safety Classification (Implemented)

Commands are now classified as Safe/Normal/Dangerous to reduce unnecessary confirmation prompts:

```go
// Safe commands (read-only): ls, cat, grep, git status, go version
sandbox.ClassifyCommand([]string{"ls", "-la"}) // CommandSafe

// Normal commands (state-modifying): touch, mkdir, npm install
sandbox.ClassifyCommand([]string{"npm", "install"}) // CommandNormal

// Dangerous commands (destructive): rm -rf, sudo, git push --force
sandbox.ClassifyCommand([]string{"rm", "-rf", "/"}) // CommandDangerous
```

Safe commands skip confirmation prompts even in permissive modes. Dangerous commands always require confirmation (unless `--dangerously-skip-prompt` is set).

### Configurable Docker CLI Path (Implemented)

Support for alternative Docker-compatible CLIs via environment variables:

```bash
# Use nerdctl instead of docker
DEPUTY_DOCKER_CLI=nerdctl deputy exec -- ls -la

# Use finch (AWS)
DEPUTY_DOCKER_CLI=finch deputy exec -- npm test

# Custom runsc path for gVisor
DEPUTY_RUNSC_PATH=/opt/gvisor/runsc deputy exec --runtime gvisor -- ls
```

See `internal/sandbox/env.go` for all environment variables.

### VM-based Sandbox Plugin (Example)

The `examples/sandbox-plugins/vz/` directory contains a reference implementation of a VM-based sandbox using Apple's Virtualization.framework:

```bash
# Install the vz plugin (macOS Apple Silicon only)
cd examples/sandbox-plugins/vz
go build -o deputy-sandbox-vz .
codesign --entitlements entitlements.plist --sign - deputy-sandbox-vz

# Use it
deputy exec --runtime plugin --plugin vz -- ls -la
```

This demonstrates the plugin protocol and provides maximum isolation via lightweight VMs.

## Future Enhancements

### 1. Apple Container Integration

For macOS with Apple Silicon, when [apple/container](https://github.com/apple/container) reaches stability:

```go
// Uses macOS Virtualization.framework
// OCI-compatible images
// Native on Apple Silicon
type AppleContainerRuntime struct {}
```

### 2. Firecracker/Lima Plugin

Hardware-assisted VMs for maximum isolation:

```yaml
# deputy-sandbox-firecracker
capabilities:
  hardware_isolation: true
  startup_time: 125ms
  linux_only: true
```

### 4. WebAssembly Runtime

For truly portable, architecture-independent sandboxing:

```yaml
# deputy-sandbox-wasm
capabilities:
  architecture_independent: true
  deterministic: true
  memory_safe: true
```

### 5. gomodjail Integration

Per-module syscall filtering for Go supply chain:

```go
// In go.mod
require (
    github.com/untrusted/module v1.0.0 // gomodjail:confined
)
```

## Comparison with Other Sandboxing Systems

### vs Gemini CLI Sandboxing

| Feature | Deputy | Gemini CLI |
|---------|--------|------------|
| Runtimes | 10+ (built-in + plugins) | Docker, Podman, sandbox-exec |
| Plugin API | Yes (MCP-like) | Proposed (Issue #3216) |
| Policy Engine | CEL-based | None |
| Audit Logging | Comprehensive | Basic |
| Network Allowlists | Yes | Limited |

### vs Docker Desktop

| Feature | Deputy | Docker Desktop |
|---------|--------|----------------|
| Purpose | Security-first isolation | Development environment |
| Default Network | Disabled | Enabled |
| Capability Dropping | Aggressive | Conservative |
| Policy Integration | Native | None |
| Audit Trail | Yes | No |

### vs gVisor

Deputy can USE gVisor as a runtime while adding:
- Policy evaluation
- Network allowlists
- Multi-runtime fallback
- Cross-platform support

## Configuration

### CLI Configuration (`.deputy.yaml`)

```yaml
sandbox:
  default_runtime: docker
  fallback_runtimes: [gvisor, sandbox-exec, none]
  default_mode: workspace-write
  default_network: none
  default_limits:
    memory: 512m
    cpu: "1.0"
    max_pids: 100

  # Runtime-specific configuration
  docker:
    image: alpine:latest
    seccomp_profile: default

  gvisor:
    platform: ptrace  # or kvm

  sandbox_exec:
    profile_path: /path/to/profile.sb

# Plugin runtimes
plugins:
  sandboxes:
    - name: deputy-sandbox-firecracker
      path: /usr/local/bin/deputy-sandbox-firecracker
```

### Policy Configuration

```yaml
# sandbox-policy.yaml
policies:
  - name: enterprise-sandbox-rules
    entrypoints: ["sandbox_execution"]
    vars:
      allowed_images: ["alpine:*", "debian:*", "gcr.io/distroless/*"]
      blocked_networks: ["169.254.169.254"]  # Block metadata service
    rules:
      - action: deny
        when: |
          config.image != "" &&
          !allowed_images.exists(i, config.image.matches(i))
        reason: "Image not in approved list"
```

## Security Considerations

### Threat Model

1. **Malicious Plugin**: A compromised extractor plugin attempts to exfiltrate data
   - Mitigation: Network isolation, filesystem restrictions, capability dropping

2. **AI Agent Escape**: An AI agent attempts to modify system files or gain persistence
   - Mitigation: Workspace-only writes, approval workflows, guardrails

3. **Supply Chain Attack**: A malicious dependency executes code during remediation
   - Mitigation: Sandboxed package manager execution, network allowlists

4. **Container Escape**: Exploiting container runtime vulnerabilities
   - Mitigation: gVisor/Firecracker for untrusted code, minimal capabilities

### Known Limitations

1. **sandbox-exec Deprecation**: macOS sandbox-exec is deprecated; Apple Container is the future
2. **Windows Support**: Limited to Docker Desktop; native sandboxing requires WSL2
3. **Resource Overhead**: VM-based isolation (Firecracker) has higher memory overhead
4. **Plugin Trust**: Plugin runtimes must be trusted; they run with Deputy's privileges

## References

### Research & Best Practices
- [NVIDIA: Code Execution Risks in Agentic AI](https://developer.nvidia.com/blog/how-code-execution-drives-key-risks-in-agentic-ai-systems/)
- [Skywork: Hardening Best Practices](https://skywork.ai/blog/ai-agent/hardening-best-practices-sandboxing-least-privilege-data-exfiltration/)
- [Claude Code Sandboxing Docs](https://code.claude.com/docs/en/sandboxing)
- [AISI: Inspect Sandboxing Toolkit](https://www.aisi.gov.uk/blog/the-inspect-sandboxing-toolkit-scalable-and-secure-ai-agent-evaluations)

### Technologies
- [Landlock LSM](https://landlock.io/)
- [go-landlock](https://github.com/landlock-lsm/go-landlock)
- [landrun](https://github.com/Zouuup/landrun)
- [gVisor](https://gvisor.dev/)
- [Firecracker](https://firecracker-microvm.github.io/)
- [Apple Container](https://github.com/apple/container)
- [alcless](https://github.com/AkihiroSuda/alcless)
- [gomodjail](https://github.com/AkihiroSuda/gomodjail)

### Industry Initiatives
- [Gemini CLI Sandboxing Plugin API](https://github.com/google-gemini/gemini-cli/issues/3216)
- [Agent Sandbox for Kubernetes](https://www.infoq.com/news/2025/12/agent-sandbox-kubernetes/)
