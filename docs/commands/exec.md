# `deputy exec`

Run a command inside a sandboxed runtime with supply chain security protections.

`deputy exec` is Deputy's first-class feature for safely running package manager
commands (`npm install`, `go get`, `pip install`, etc.) and build scripts. It
protects against malicious install scripts, postinstall hooks, and other supply
chain attack vectors through:

- **Workspace isolation**: Prevent untrusted code from modifying your original files
- **File masking**: Hide secrets (`.env`, credentials) while exposing lockfiles
- **Network allowlists**: Restrict outbound connections to trusted registries
- **Resource limits**: Cap CPU, memory, and process counts

Deputy supports multiple isolation runtimes (Docker, gVisor, vz plugin, sandbox-exec)
with consistent security semantics across all of them.

## Synopsis

```
deputy exec -- <command> [args...]
```

## Flags

### Core Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--runtime` | `docker` | Sandbox runtime: `docker`, `gvisor`, `none`, `sandbox-exec`, `plugin` |
| `--plugin` | | Plugin name when using `--runtime plugin` (e.g., `vz`) |
| `--mode` | `workspace-write` | Filesystem mode: `read-only`, `workspace-write`, `full-access`, `network-isolated`, `ephemeral` |
| `--network` | `none` | Network mode: `none`, `host`, `bridge`, `allowlist` |
| `--network-allow` | | Allowed hosts for allowlist mode (repeatable) |
| `--image` | | Container image (Docker/gVisor) |
| `--workspace` | `.` | Workspace directory to mount |
| `--no-workspace` | `false` | Disable workspace mounting |
| `--work-dir` | | Working directory inside the sandbox |
| `--env` | | Environment variables (`KEY=VALUE`, repeatable) |
| `--stdin` | | Stdin source file path or `-` |
| `--timeout` | | Execution timeout (e.g., `30s`, `5m`) |
| `--policy` | | Policy file or bundle to enforce (repeatable) |
| `--verbose` | `false` | Show non-fatal sandbox warnings |
| `--exec-allow` | | Allow additional executables by path or command name (repeatable) |
| `--dangerously-skip-prompt` | `false` | Skip confirmation for dangerous modes |

### Workspace Isolation Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--workspace-isolation` | `direct` | Isolation mode: `direct`, `snapshot`, `overlay`, `tmpfs`, `git-worktree` |
| `--isolation-size-limit` | `1g` | Size limit for overlay/tmpfs upper layer |
| `--preserve-workspace` | `false` | Preserve isolated workspace after execution for review |

### File Masking Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--mask-preset` | | Masking preset (repeatable): `secrets`, `git`, `ide`, `build`, `node-modules`, `supply-chain` |
| `--mask-hide` | | Glob pattern for files to hide (repeatable) |
| `--mask-expose` | | Glob pattern for files to expose even if masked (repeatable) |

### Host Path Access Flags (Host-native sandboxes)

These flags control access to host filesystem paths for host-native sandboxes
(`sandbox-exec`, `landlock`, `bwrap`). Container runtimes use `--mount` instead.

| Flag | Default | Description |
| --- | --- | --- |
| `--read-path` | | Additional host path to allow reading (repeatable, supports `~`) |
| `--exec-path` | | Additional host path to allow executing (repeatable, supports `~`) |
| `--write-path` | | Additional host path to allow writing (repeatable, supports `~`) |
| `--profile` | | Named profile for common configurations (repeatable) |

### Built-in Profiles

Profiles expand to commonly-needed path configurations:

| Profile | Read Paths | Exec Paths | Write Paths |
| --- | --- | --- | --- |
| `git` | `~/.gitconfig`, `~/.config/git`, `~/.ssh` | | |
| `node` | `~/.npm`, `~/.npmrc`, `~/.nvm`, `~/.config/npm` | | `~/.npm/_cacache` |
| `go` | `~/.go`, `~/go`, `~/.cache/go-build` | `~/go/bin` | `~/.cache/go-build` |
| `python` | `~/.pyenv`, `~/.local/lib/python*`, `~/.config/pip` | `~/.pyenv/shims`, `~/.local/bin` | |
| `rust` | `~/.cargo`, `~/.rustup` | `~/.cargo/bin`, `~/.rustup/toolchains` | |
| `xdg` | `~/.config`, `~/.local/share`, `~/.cache` | | `~/.cache` |
| `codex` | `~/.codex`, `~/.config/codex` | | |
| `claude` | `~/.claude`, `~/.config/claude`, `~/.anthropic` | | |

## Runtime Comparison

| Runtime | Platform | Network Isolation | Filesystem Isolation | Resource Limits |
| --- | --- | --- | --- | --- |
| `docker` | All | Yes | Yes | Yes |
| `gvisor` | Linux | Yes | Yes | Yes |
| `plugin` (vz) | macOS ARM64 | Yes | Yes | Yes |
| `sandbox-exec` | macOS | Limited | Limited | No |
| `none` | All | No | No | No |

## Plugin Runtime (vz)

The `vz` plugin provides VM-based isolation on macOS Apple Silicon using Apple's
Virtualization.framework. Each command runs in a lightweight Linux VM.

```console
# Run command in VM sandbox
$ deputy exec --runtime plugin --plugin vz -- uname -a
Linux (none) 6.8.0-90-generic #91 ... aarch64 GNU/Linux
```

Requirements:
- macOS 11.0+ (Big Sur or later)
- Apple Silicon (ARM64)
- Plugin binary with virtualization entitlements
- Linux kernel and rootfs in `~/.deputy/vz/`

## Network Allowlists

Use `--network allowlist` with `--network-allow` to permit specific endpoints:

```console
# Allow only Go module proxy
$ deputy exec --network allowlist \
    --network-allow proxy.golang.org:443 \
    --network-allow sum.golang.org:443 \
    -- go get github.com/example/pkg@v1.0.0
```

For remediation commands, Deputy can automatically apply ecosystem-appropriate
allowlists (see `deputy fix --sandbox`).

## Workspace Isolation

Workspace isolation provides copy-on-write style protection, preventing sandbox
commands from modifying your original workspace until you explicitly approve changes.
This is critical for running untrusted code like package manager install scripts.

### Isolation Modes

| Mode | Description | Use Case |
| --- | --- | --- |
| `direct` | Mount workspace directly (default) | Trusted commands, fastest |
| `snapshot` | Copy workspace to temp directory | Safe experimentation, rollback |
| `overlay` | Copy-on-write overlay filesystem | Linux-only, efficient changes |
| `tmpfs` | Memory-backed workspace | Ephemeral, no disk writes |
| `git-worktree` | Git worktree for isolation | Git repos, branch-based isolation |

### Examples

```console
# Run npm install in an isolated snapshot (changes not applied to original)
$ deputy exec --runtime docker --workspace-isolation snapshot --image node:22-alpine -- npm install

# Preserve workspace for manual review after execution
$ deputy exec --runtime docker --workspace-isolation snapshot --preserve-workspace --image node:22-alpine -- npm install
# Output: Isolated workspace preserved at /tmp/deputy-docker-workspace-xyz

# Run with size-limited overlay
$ deputy exec --runtime docker --workspace-isolation overlay --isolation-size-limit 512m --image rust:1.75-alpine -- cargo build
```

## File Masking

File masking hides sensitive files from the sandbox while exposing only what's
needed. This protects secrets while allowing package managers to read lockfiles.

### Presets

| Preset | Hidden Files | Exposed Files |
| --- | --- | --- |
| `secrets` | `.env*`, `*.pem`, `*.key`, credentials | None |
| `git` | `.git/**` | None |
| `ide` | `.vscode/`, `.idea/`, `*.swp` | None |
| `build` | `dist/`, `build/`, `__pycache__/` | None |
| `node-modules` | `node_modules/**` | None |
| `supply-chain` | All of the above | `package*.json`, `go.mod`, `Cargo.toml`, lockfiles |

### Examples

```console
# Hide secrets but expose lockfiles for npm audit
$ deputy exec --runtime docker --mask-preset supply-chain --image node:22-alpine -- npm audit

# Combine presets for maximum safety
$ deputy exec --runtime docker --mask-preset secrets --mask-preset git --image golang:1.22-alpine -- go build ./...

# Custom masking rules
$ deputy exec --runtime docker --mask-hide '.env*' --mask-hide '*.pem' --mask-expose 'package*.json' --image node:22-alpine -- npm install

# AI agent workflow: isolate workspace and mask secrets
$ deputy exec --runtime docker \
    --workspace-isolation snapshot \
    --mask-preset supply-chain \
    --preserve-workspace \
    --image node:22-alpine \
    -- npm install
```

## Host Path Access (sandbox-exec, landlock, bwrap)

Host-native sandboxes like `sandbox-exec` run directly on the host filesystem
rather than in containers. They need explicit permission to access paths outside
the workspace and default system paths.

### Using Profiles

Profiles are the recommended way to grant access for common tools:

```console
# Allow git operations (access to ~/.gitconfig, ~/.ssh)
$ deputy exec --runtime sandbox-exec --profile git -- git status

# Allow Go toolchain paths with network for module downloads
$ deputy exec --runtime sandbox-exec --profile go --network host -- go build ./...

# Combine multiple profiles
$ deputy exec --runtime sandbox-exec --profile git --profile node -- npm install

# Run Codex with its config directory
$ deputy exec --runtime sandbox-exec --profile codex -- codex exec "describe this code"
```

### Using Explicit Paths

For one-off access or custom tools, use explicit path flags:

```console
# Allow reading a specific config directory
$ deputy exec --runtime sandbox-exec --read-path ~/.myapp -- ./myapp

# Allow executing from a custom bin directory
$ deputy exec --runtime sandbox-exec --exec-path /opt/mycompany/bin -- mytool

# Allow writing to a cache directory
$ deputy exec --runtime sandbox-exec --write-path ~/.cache/myapp -- ./myapp build

# Combine profiles with explicit paths
$ deputy exec --runtime sandbox-exec --profile git --read-path ~/.codex -- codex exec "..."
```

## macOS `sandbox-exec` Limitations

The `sandbox-exec` runtime is **deprecated by Apple** and provides best-effort
isolation only.

- No network allowlists (only `none` or full network).
- No additional mounts (use `--read-path`, `--write-path` instead).
- No resource limits (memory/CPU/PIDs).
- Use `--exec-allow` or `--exec-path` to run binaries outside the default exec allowlist.
- Use `--profile` for common tool configurations (git, node, go, etc.).

Prefer container runtimes or the vz plugin when possible.

## Security Features

Deputy's sandbox system includes multiple security layers:

1. **Command classification**: Dangerous commands require confirmation
2. **Environment filtering**: Blocks injection vectors (LD_PRELOAD, etc.)
3. **Path validation**: Blocks access to sensitive system paths
4. **Capability dropping**: Removes dangerous Linux capabilities
5. **Policy evaluation**: CEL policies for fine-grained control

## Examples

### Basic Usage

```console
# Run a read-only command
$ deputy exec --runtime docker --mode read-only --image alpine:3.19 -- ls -la

# Run with Docker using a specific image
$ deputy exec --runtime docker --image alpine:3.19 -- echo hello

# Run npm install with limited network access
$ deputy exec --runtime docker \
    --network allowlist \
    --network-allow registry.npmjs.org:443 \
    --image node:22-alpine \
    -- npm install
```

### Safe Package Manager Operations

```console
# Run npm install in an isolated snapshot (protect your workspace)
$ deputy exec --runtime docker \
    --workspace-isolation snapshot \
    --mask-preset supply-chain \
    --image node:22-alpine \
    -- npm install

# Run go get with network allowlist
$ deputy exec --runtime docker \
    --network allowlist \
    --network-allow proxy.golang.org:443 \
    --network-allow sum.golang.org:443 \
    --image golang:1.22-alpine \
    -- go get -d ./...

# Run pip install with secrets protected
$ deputy exec --runtime docker \
    --workspace-isolation snapshot \
    --mask-preset secrets \
    --image python:3.12-slim \
    -- pip install -r requirements.txt
```

### Runtime Selection

```console
# VM-based isolation with vz plugin (macOS ARM64)
$ deputy exec --runtime plugin --plugin vz -- go build ./...

# macOS sandbox-exec (deprecated, best-effort)
$ deputy exec --runtime sandbox-exec --mode read-only -- ls -la

# Skip confirmation for scripting (Docker)
$ deputy exec --runtime docker --mode full-access --dangerously-skip-prompt --image alpine:3.19 -- ./build.sh
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded |
| `1` | Command failed or sandbox error |
| `124` | Command timed out (when `--timeout` is set) |

## See Also

- [Fix command](fix.md) - Uses sandboxed execution for AI agents
- [Sandbox policies](../reference/policy-inputs.md#sandbox-entrypoints) - CEL policies for sandbox control
- [Agents guide](../guides/agents.md) - AI-assisted workflows with sandboxing

## Code Pointers

- CLI: [`internal/cli/cmd/exec.go`](../../internal/cli/cmd/exec.go)
- Sandbox: [`internal/sandbox`](../../internal/sandbox)
- VZ Plugin: [`examples/sandbox-plugins/vz`](../../examples/sandbox-plugins/vz)
