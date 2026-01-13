# Deputy Sandbox Capability Model

## Overview

This document defines the capability model for Deputy's sandbox system - the permissions, restrictions, and security boundaries that govern sandboxed execution.

## Core Capability Dimensions

### 1. Filesystem Capabilities

```
┌─────────────────────────────────────────────────────────────────┐
│                    Filesystem Access Spectrum                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EPHEMERAL ─────► READ_ONLY ─────► WORKSPACE_WRITE ─────► FULL  │
│                                                                 │
│  Changes         Can read         Read/write in      Unrestricted│
│  discarded       workspace,       workspace only     filesystem │
│  after exec      no writes                           access     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Mode Details

| Mode | Read Workspace | Write Workspace | Read System | Write System | Use Case |
|------|----------------|-----------------|-------------|--------------|----------|
| `MODE_EPHEMERAL` | Yes | Yes (discarded) | No | No | Testing destructive operations |
| `MODE_READ_ONLY` | Yes | No | No | No | Safe exploration, analysis |
| `MODE_WORKSPACE_WRITE` | Yes | Yes | Limited | No | Normal development (default) |
| `MODE_NETWORK_ISOLATED` | Yes | Yes | Limited | No | Offline builds |
| `MODE_FULL_ACCESS` | Yes | Yes | Yes | Yes | Trusted code only |

#### System Read Access (WORKSPACE_WRITE mode)

```go
// Paths available in workspace-write mode
var SystemReadPaths = []string{
    "/usr/bin",           // System binaries
    "/usr/lib",           // System libraries
    "/etc/resolv.conf",   // DNS resolution (when network enabled)
    "/etc/hosts",         // Host resolution
    "/etc/ssl/certs",     // SSL certificates
    "/etc/passwd",        // User info (read-only)
    "/tmp",               // Temp storage
}

// Paths NEVER available (even in full-access mode by default)
var DeniedPaths = []string{
    "/etc/shadow",        // Password hashes
    "/etc/sudoers",       // Sudo configuration
    "/root",              // Root home
    "/proc/1",            // Host init process
    "/sys/firmware",      // UEFI/BIOS
    "/dev/mem",           // Physical memory
    "/dev/kmem",          // Kernel memory
}
```

### 2. Network Capabilities

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Access Spectrum                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NONE ─────────► ALLOWLIST ─────────► BRIDGE ─────────► HOST    │
│                                                                 │
│  No network      Only specified     NAT to host,      Full host │
│  access          hosts/ports        new IP space      network   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Mode Details

| Mode | Outbound | Inbound | DNS | Use Case |
|------|----------|---------|-----|----------|
| `NETWORK_MODE_NONE` | No | No | No | Maximum security (default) |
| `NETWORK_MODE_ALLOWLIST` | Specified only | No | Optional | Package downloads |
| `NETWORK_MODE_BRIDGE` | Yes (NAT) | Via port mapping | Yes | Development servers |
| `NETWORK_MODE_HOST` | Full | Full | Yes | Legacy compatibility |

#### Allowlist Specification

```yaml
# Network allowlist formats
network_allowlist:
  # Exact host:port
  - "proxy.golang.org:443"
  - "registry.npmjs.org:443"

  # Wildcard subdomain
  - "*.github.com:443"
  - "*.githubusercontent.com:443"

  # CIDR notation
  - "10.0.0.0/8:*"           # Internal network, any port
  - "192.168.1.0/24:80,443"  # Local network, specific ports

  # DNS resolution (resolved at connection time)
  - "api.example.com:443"
```

### 3. Process Capabilities

#### Linux Capabilities

```go
// Capability tiers
type CapabilityTier int

const (
    // Tier 1: Always dropped (dangerous)
    TierDangerous CapabilityTier = iota
    // Tier 2: Dropped by default, can be added back
    TierRestricted
    // Tier 3: Included in minimal set
    TierMinimal
    // Tier 4: Included in default set
    TierDefault
)

var CapabilityClassification = map[string]CapabilityTier{
    // Tier 1: NEVER granted
    "CAP_SYS_ADMIN":        TierDangerous,  // Mount, namespace escape
    "CAP_SYS_PTRACE":       TierDangerous,  // Debug other processes
    "CAP_SYS_MODULE":       TierDangerous,  // Load kernel modules
    "CAP_SYS_RAWIO":        TierDangerous,  // Direct I/O
    "CAP_SYS_BOOT":         TierDangerous,  // Reboot system
    "CAP_NET_ADMIN":        TierDangerous,  // Network configuration
    "CAP_DAC_READ_SEARCH":  TierDangerous,  // Bypass read permissions

    // Tier 2: Special request only
    "CAP_DAC_OVERRIDE":     TierRestricted, // Bypass all permissions
    "CAP_SYS_CHROOT":       TierRestricted, // Change root
    "CAP_SETPCAP":          TierRestricted, // Modify capabilities
    "CAP_SETFCAP":          TierRestricted, // Set file capabilities
    "CAP_AUDIT_WRITE":      TierRestricted, // Write audit log

    // Tier 3: Minimal (for most sandboxed workloads)
    "CAP_CHOWN":            TierMinimal,    // Change file ownership
    "CAP_FOWNER":           TierMinimal,    // Bypass owner checks
    "CAP_FSETID":           TierMinimal,    // Set SUID/SGID
    "CAP_KILL":             TierMinimal,    // Send signals
    "CAP_SETGID":           TierMinimal,    // Set GID
    "CAP_SETUID":           TierMinimal,    // Set UID

    // Tier 4: Default (more permissive, still safe)
    "CAP_NET_BIND_SERVICE": TierDefault,    // Bind < 1024
    "CAP_NET_RAW":          TierDefault,    // Raw sockets (ping)
    "CAP_MKNOD":            TierDefault,    // Create special files
}
```

#### Seccomp Profiles

```go
// Profile strictness levels
type SeccompProfile string

const (
    // Block dangerous syscalls, allow most normal operations
    SeccompDefault SeccompProfile = "default"

    // Stricter: block more syscalls, suitable for most workloads
    SeccompStrict SeccompProfile = "strict"

    // Minimal: only allow essential syscalls
    SeccompMinimal SeccompProfile = "minimal"

    // Custom: user-provided profile path
    SeccompCustom SeccompProfile = "custom"
)

// Syscalls blocked in 'strict' profile (beyond default)
var StrictBlockedSyscalls = []string{
    "ptrace",           // Process tracing
    "process_vm_readv", // Read other process memory
    "process_vm_writev",// Write other process memory
    "personality",      // Change execution domain
    "swapon",           // Enable swap
    "swapoff",          // Disable swap
    "syslog",           // Read kernel logs
    "kexec_load",       // Load new kernel
    "kexec_file_load",
    "perf_event_open",  // Performance monitoring
    "bpf",              // eBPF operations
    "userfaultfd",      // User-space page fault handling
}
```

### 4. Resource Capabilities

```go
// Resource limit presets
type ResourcePreset string

const (
    ResourceMinimal   ResourcePreset = "minimal"   // Very constrained
    ResourceDefault   ResourcePreset = "default"   // Normal operations
    ResourceGenerous  ResourcePreset = "generous"  // Heavy workloads
    ResourceUnlimited ResourcePreset = "unlimited" // No limits (dangerous)
)

var ResourcePresets = map[ResourcePreset]ResourceLimits{
    ResourceMinimal: {
        Memory:       "128m",
        CPU:          "0.25",
        MaxPIDs:      32,
        MaxFiles:     128,
        DiskQuota:    10 * 1024 * 1024,    // 10MB
        MaxTime:      30 * time.Second,
    },
    ResourceDefault: {
        Memory:       "512m",
        CPU:          "1.0",
        MaxPIDs:      256,
        MaxFiles:     1024,
        DiskQuota:    100 * 1024 * 1024,   // 100MB
        MaxTime:      5 * time.Minute,
    },
    ResourceGenerous: {
        Memory:       "2g",
        CPU:          "4.0",
        MaxPIDs:      1024,
        MaxFiles:     4096,
        DiskQuota:    1024 * 1024 * 1024,  // 1GB
        MaxTime:      30 * time.Minute,
    },
    ResourceUnlimited: {
        // No limits - use with extreme caution
    },
}
```

## Execution Source Profiles

Different execution sources have different default capabilities:

### Plugin Execution

```go
var PluginCapabilityProfile = CapabilityProfile{
    FilesystemMode:   MODE_READ_ONLY,
    NetworkMode:      NETWORK_MODE_NONE,
    ResourcePreset:   ResourceMinimal,
    CapabilityTier:   TierMinimal,
    SeccompProfile:   SeccompStrict,

    // Plugins declare their requirements
    AllowUpgrade:     true,  // Can request more via manifest
    RequireApproval:  true,  // Upgrades need user approval
}
```

### AI Agent Execution

```go
var AgentCapabilityProfile = CapabilityProfile{
    FilesystemMode:   MODE_WORKSPACE_WRITE,
    NetworkMode:      NETWORK_MODE_NONE,
    ResourcePreset:   ResourceDefault,
    CapabilityTier:   TierMinimal,
    SeccompProfile:   SeccompDefault,

    // Agents have approval workflows
    ApprovalPolicy: &ApprovalPolicy{
        RequireApproval: []CapabilityEscalation{
            {From: MODE_WORKSPACE_WRITE, To: MODE_FULL_ACCESS},
            {From: NETWORK_MODE_NONE, To: NETWORK_MODE_HOST},
        },
        AutoApprove: []CapabilityEscalation{
            {From: NETWORK_MODE_NONE, To: NETWORK_MODE_ALLOWLIST},
        },
        AlwaysDeny: []CapabilityEscalation{
            {To: TierDangerous}, // Never grant dangerous caps
        },
    },

    // Guardrails for agent operations
    Guardrails: &Guardrails{
        DenyCommands: []string{
            "sudo *",
            "curl * | *sh",
            "git push --force *",
        },
        DenyPaths: []string{
            "~/.ssh/*",
            "~/.aws/*",
            "*.pem",
        },
        HighRiskPatterns: []string{
            "git push --force",
            "git reset --hard",
            "npm publish",
        },
    },
}
```

### Remediation Execution

```go
var RemediationCapabilityProfile = CapabilityProfile{
    FilesystemMode:   MODE_WORKSPACE_WRITE,
    NetworkMode:      NETWORK_MODE_ALLOWLIST,  // Need to download packages
    ResourcePreset:   ResourceDefault,
    CapabilityTier:   TierMinimal,
    SeccompProfile:   SeccompDefault,

    // Package manager network allowlist
    NetworkAllowlist: []string{
        // Go
        "proxy.golang.org:443",
        "sum.golang.org:443",
        "storage.googleapis.com:443",

        // npm
        "registry.npmjs.org:443",

        // PyPI
        "pypi.org:443",
        "files.pythonhosted.org:443",

        // RubyGems
        "rubygems.org:443",

        // Container registries
        "*.docker.io:443",
        "ghcr.io:443",
        "*.gcr.io:443",
    },

    // Allowed executables
    ExecAllowlist: []string{
        "go", "npm", "yarn", "pip", "bundle",
        "cargo", "composer", "mvn", "gradle",
    },
}
```

### Manual Exec (CLI)

```go
var ExecCapabilityProfile = CapabilityProfile{
    FilesystemMode:   MODE_WORKSPACE_WRITE,  // User can override
    NetworkMode:      NETWORK_MODE_NONE,     // User can override
    ResourcePreset:   ResourceDefault,       // User can override
    CapabilityTier:   TierMinimal,
    SeccompProfile:   SeccompDefault,

    // CLI allows full customization
    AllowOverride:    true,
    WarnOnDangerous:  true,  // Warn but allow dangerous options
}
```

### Server Execution

```go
var ServerCapabilityProfile = CapabilityProfile{
    // Server mode CANNOT execute local code
    LocalExecution:   false,

    // Only these operations are allowed
    AllowedOperations: []string{
        "scan",          // Vulnerability scanning
        "sbom",          // SBOM generation
        "list",          // Package listing
        "policy_eval",   // Policy evaluation
        "diff",          // Dependency diffing
    },

    // These require local mode
    DeniedOperations: []string{
        "fix_apply",           // Remediation execution
        "agent_execute",       // AI agent execution
        "plugin_execute",      // Plugin execution
        "exec",                // Direct command execution
    },
}
```

## Capability Negotiation

When a component requests capabilities beyond its profile:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Capability Request Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Component requests execution with capabilities              │
│                        │                                        │
│                        ▼                                        │
│  2. Manager compares against source profile                     │
│                        │                                        │
│            ┌───────────┴───────────┐                            │
│            │                       │                            │
│            ▼                       ▼                            │
│  3a. Within profile?        3b. Exceeds profile?                │
│            │                       │                            │
│            ▼                       ▼                            │
│     Execute directly       4. Check policy engine               │
│                                    │                            │
│                    ┌───────────────┼───────────────┐            │
│                    │               │               │            │
│                    ▼               ▼               ▼            │
│              5a. Deny       5b. Require       5c. Allow        │
│                   │          Approval              │            │
│                   │               │               │            │
│                   ▼               ▼               ▼            │
│              Error           User prompt       Execute          │
│                                   │                             │
│                          ┌───────┴───────┐                      │
│                          │               │                      │
│                          ▼               ▼                      │
│                      Approved        Denied                     │
│                          │               │                      │
│                          ▼               ▼                      │
│                      Execute          Error                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Policy Language

```yaml
# capability-policy.yaml
policies:
  - name: capability-escalation
    entrypoints: ["sandbox_execution"]
    rules:
      # Deny dangerous capabilities always
      - action: deny
        when: |
          config.add_capabilities.exists(c, c in [
            "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"
          ])
        reason: "Dangerous capabilities not allowed"

      # Require approval for full filesystem access
      - action: require_approval
        when: |
          config.mode == "MODE_FULL_ACCESS" &&
          context.source != "EXECUTION_SOURCE_EXEC"
        reason: "Full filesystem access requires approval"

      # Auto-approve package registry access for remediation
      - action: allow
        when: |
          context.source == "EXECUTION_SOURCE_REMEDIATION" &&
          config.network_mode == "NETWORK_MODE_ALLOWLIST" &&
          config.network_allowlist.all(h,
            h.matches("^(proxy\\.golang\\.org|registry\\.npmjs\\.org|pypi\\.org)")
          )
        reason: "Package registry access for remediation"

      # Deny network access for plugins by default
      - action: deny
        when: |
          context.source == "EXECUTION_SOURCE_PLUGIN" &&
          config.network_mode != "NETWORK_MODE_NONE"
        reason: "Plugins cannot access network"
```

## Capability Reporting

Runtimes report their capabilities:

```proto
message RuntimeCapabilities {
  // Isolation features
  bool network_isolation = 1;
  bool filesystem_isolation = 2;
  bool resource_limits = 3;

  // Linux security modules
  bool seccomp = 4;
  bool apparmor = 5;
  bool selinux = 6;
  bool landlock = 7;

  // Namespace support
  bool user_namespaces = 8;
  bool pid_namespaces = 9;
  bool network_namespaces = 10;
  bool mount_namespaces = 11;

  // Operational features
  bool rootless = 12;
  bool gpu_support = 13;
  bool streaming_output = 14;
  bool interactive_stdin = 15;

  // Isolation strength (1-10 scale)
  int32 isolation_score = 16;

  // Platform requirements
  repeated string supported_platforms = 17;
  string min_kernel_version = 18;
}
```

### Isolation Score Calculation

```go
func CalculateIsolationScore(caps *RuntimeCapabilities) int32 {
    score := 0

    // Base isolation features (up to 5 points)
    if caps.FilesystemIsolation { score += 1 }
    if caps.NetworkIsolation { score += 1 }
    if caps.PidNamespaces { score += 1 }
    if caps.MountNamespaces { score += 1 }
    if caps.UserNamespaces { score += 1 }

    // Security modules (up to 3 points)
    if caps.Seccomp { score += 1 }
    if caps.Apparmor || caps.Selinux { score += 1 }
    if caps.Landlock { score += 1 }

    // Rootless adds security (1 point)
    if caps.Rootless { score += 1 }

    // Hardware isolation is the gold standard (bonus)
    // Firecracker, VMs add +2 bonus
    // gVisor adds +1 bonus

    return int32(score)
}
```

## Capability Requirements by Ecosystem

Different package ecosystems have different capability requirements:

| Ecosystem | Filesystem | Network | Typical Executables |
|-----------|------------|---------|---------------------|
| Go | workspace-write | allowlist (proxy.golang.org) | go |
| npm | workspace-write | allowlist (registry.npmjs.org) | npm, node |
| Python | workspace-write | allowlist (pypi.org) | pip, python |
| Ruby | workspace-write | allowlist (rubygems.org) | bundle, ruby |
| Rust | workspace-write | allowlist (crates.io) | cargo, rustc |
| Java | workspace-write | allowlist (repo1.maven.org) | mvn, gradle, java |
| Docker | read-only | allowlist (registries) | docker, crane |

## Appendix: Default Capability Matrix

| Source | FS Mode | Network | Memory | CPU | PIDs | Timeout | Seccomp |
|--------|---------|---------|--------|-----|------|---------|---------|
| Plugin | read-only | none | 128m | 0.25 | 32 | 30s | strict |
| Agent | workspace-write | none | 512m | 1.0 | 256 | 5m | default |
| Remediation | workspace-write | allowlist | 512m | 1.0 | 256 | 5m | default |
| Exec (default) | workspace-write | none | 512m | 1.0 | 256 | none | default |
| Server | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
