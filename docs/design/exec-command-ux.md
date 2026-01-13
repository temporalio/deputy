# Deputy Exec Command UX Design

## Philosophy

The `deputy exec` command embodies Deputy's security-first approach: **safe by default, powerful when needed**. Like Docker, it provides a familiar interface for running commands in isolated environments, but with security as the primary concern rather than portability.

## Design Principles

### 1. Progressive Disclosure

```
Simple ─────────────────────────────────────────────► Complex

deputy exec -- ls                    # Just works, safe defaults
deputy exec --mode read-only -- ls   # Explicit about restrictions
deputy exec --runtime gvisor \       # Full control
  --network allowlist \
  --network-allow proxy.golang.org:443 \
  --memory 1g \
  -- go build ./...
```

### 2. Docker-like Familiarity

Users familiar with Docker will feel at home:

| Docker | Deputy |
|--------|--------|
| `docker run alpine ls` | `deputy exec -- ls` |
| `docker run -v $PWD:/work alpine ls` | `deputy exec --workspace . -- ls` |
| `docker run --network none alpine ls` | `deputy exec --network none -- ls` |
| `docker run --read-only alpine ls` | `deputy exec --mode read-only -- ls` |
| `docker run --memory 512m alpine ls` | `deputy exec --memory 512m -- ls` |

### 3. Explicit Danger Warnings

```bash
# Safe (default) - changes confined to workspace
$ deputy exec -- npm install

# Needs confirmation - system-wide installation
$ deputy exec --mode full-access -- npm install -g typescript
Warning: Full filesystem access requested. This allows the command to modify
any file on your system.

Continue? [y/N]:
```

### 4. Helpful Errors

```bash
$ deputy exec --runtime gvisor -- ls
Error: gVisor runtime is not available

Reason: runsc not found in PATH

To install gVisor:
  # On Debian/Ubuntu
  curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
  sudo apt update && sudo apt install -y runsc

Available runtimes:
  docker (default)  ✓ available
  sandbox-exec      ✓ available (macOS only)
  none              ✓ available (no isolation)
```

## Command Structure

### Basic Syntax

```
deputy exec [flags] -- <command> [args...]
```

The `--` separator is REQUIRED. This:
- Prevents flag parsing ambiguity
- Makes it clear where deputy flags end and command begins
- Aligns with Unix conventions (like `ssh`, `env`)

### Examples

```bash
# Basic execution
deputy exec -- ls -la

# Specify runtime
deputy exec --runtime docker -- go build ./...
deputy exec --runtime gvisor -- npm install
deputy exec --runtime sandbox-exec -- swift build

# Filesystem modes
deputy exec --mode read-only -- find . -name "*.go"
deputy exec --mode ephemeral -- npm run clean && npm install
deputy exec --mode full-access -- cat ~/.gitconfig  # Requires confirmation

# Network modes
deputy exec --network none -- go build ./...       # Default: no network
deputy exec --network allowlist --network-allow proxy.golang.org:443 -- go mod download
deputy exec --network host -- curl https://api.example.com

# Resource limits
deputy exec --memory 1g --cpu 2.0 -- npm run build
deputy exec --max-pids 50 --timeout 30s -- go test ./...

# Policy enforcement
deputy exec --policy sandbox-policy.yaml -- ./untrusted-script.sh

# Combine options
deputy exec \
  --runtime gvisor \
  --mode workspace-write \
  --network allowlist \
  --network-allow "*.golang.org:443" \
  --memory 2g \
  --timeout 10m \
  -- go build -o myapp ./...
```

## Flags Reference

### Runtime Selection

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--runtime` | `-r` | `docker` | Sandbox runtime |
| `--plugin` | | | Plugin name (when `--runtime=plugin`) |
| `--image` | `-i` | `alpine:latest` | Container image (container runtimes) |

### Filesystem Access

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--mode` | `-m` | `workspace-write` | Filesystem access mode |
| `--workspace` | `-w` | `.` | Host directory to mount |
| `--no-workspace` | | `false` | Disable workspace mounting |
| `--work-dir` | | workspace root | Working directory inside sandbox |

Mode values:
- `read-only` / `ro`: Can read workspace, cannot write
- `workspace-write` / `rw`: Read/write in workspace only (default)
- `network-isolated` / `ni`: Workspace write + no network
- `ephemeral`: Changes discarded after execution
- `full-access` / `full`: Unrestricted (requires confirmation)

### Network Access

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--network` | `-n` | `none` | Network access mode |
| `--network-allow` | | | Allowed hosts for allowlist mode |

Network values:
- `none`: No network access (default, most secure)
- `allowlist`: Only specified hosts allowed
- `bridge`: NAT to host network
- `host`: Full host network access (least secure)

### Resource Limits

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--memory` | | `512m` | Memory limit (e.g., `256m`, `2g`) |
| `--cpu` | | `1.0` | CPU limit (cores, e.g., `0.5`, `4.0`) |
| `--max-pids` | | `256` | Maximum processes |
| `--max-files` | | `1024` | Maximum open files |
| `--disk-quota` | | | Disk usage limit in bytes |
| `--timeout` | `-t` | none | Execution timeout (e.g., `30s`, `5m`) |

### Security

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | | Policy file(s) to enforce |
| `--exec-allow` | | Additional allowed executables |
| `--drop-cap` | | Linux capabilities to drop |
| `--add-cap` | | Linux capabilities to add |
| `--seccomp` | `default` | Seccomp profile (default/strict/minimal/path) |

### Environment & I/O

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--env` | `-e` | | Environment variable (KEY=VALUE) |
| `--env-file` | | | File with environment variables |
| `--stdin` | | | Stdin source (file path or `-` for stdin) |

### Output & Debugging

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose` | `false` | Show non-fatal warnings |
| `--quiet` | `false` | Suppress non-error output |
| `--json` | `false` | Output events as JSON |
| `--dry-run` | `false` | Show what would be executed |

## Subcommands

### List Runtimes

```bash
$ deputy exec runtimes
Available sandbox runtimes:

RUNTIME       VERSION    STATUS       ISOLATION   NOTES
docker        24.0.5     available    container   Default runtime
gvisor        20231218   available    userspace   Strongest isolation
sandbox-exec  -          available    seatbelt    macOS native
none          -          available    none        No isolation
firecracker   1.6.0      unavailable  microvm     Requires KVM (plugin)

Default: docker
```

With verbose info:

```bash
$ deputy exec runtimes --verbose
docker:
  Status: available
  Version: 24.0.5
  Capabilities:
    ✓ Network isolation
    ✓ Filesystem isolation
    ✓ Resource limits
    ✓ Seccomp
    ✓ Streaming output
  Supported modes: read-only, workspace-write, full-access, network-isolated, ephemeral
  Notes: Cross-platform via Docker Desktop

gvisor:
  Status: available
  Version: 20231218
  Capabilities:
    ✓ Network isolation
    ✓ Filesystem isolation
    ✓ Resource limits
    ✓ Seccomp (user-space)
    ✓ User namespaces
  Supported modes: read-only, workspace-write, ephemeral
  Notes: Strongest isolation, Linux only
...
```

### Explain Configuration

```bash
$ deputy exec explain --mode workspace-write --network none
Configuration explanation:

Filesystem mode: workspace-write
  - Can READ files in: /Users/you/project (workspace)
  - Can WRITE files in: /Users/you/project (workspace)
  - CANNOT access: /etc, /usr, /home (except workspace)
  - System paths: Read-only access to /usr/bin, /lib, /etc/ssl/certs

Network mode: none
  - CANNOT make any network connections
  - DNS resolution: disabled
  - Suitable for: offline builds, analysis, testing

Resource limits:
  - Memory: 512MB (default)
  - CPU: 1.0 core (default)
  - Max processes: 256
  - Max open files: 1024

Security:
  - Linux capabilities: minimal set (CHOWN, FOWNER, SETUID, SETGID, KILL)
  - Seccomp: default Docker profile
  - Environment: dangerous variables filtered (LD_PRELOAD, etc.)
```

## Interactive Prompts

### Dangerous Mode Confirmation

```bash
$ deputy exec --mode full-access -- cat /etc/hosts

╭─────────────────────────────────────────────────────────────╮
│  ⚠  Warning: Full filesystem access requested               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  This mode allows the command to:                           │
│  • Read and write ANY file on your system                   │
│  • Access files outside the workspace                       │
│  • Modify system configuration                              │
│                                                             │
│  Command: cat /etc/hosts                                    │
│  Workspace: /Users/you/project                              │
│                                                             │
│  Consider safer alternatives:                               │
│  • --mode workspace-write (access workspace only)           │
│  • Copy needed files into workspace first                   │
│                                                             │
╰─────────────────────────────────────────────────────────────╯

Continue with full filesystem access? [y/N]:
```

### Network Access Warning

```bash
$ deputy exec --network host -- curl https://api.example.com

╭─────────────────────────────────────────────────────────────╮
│  ⚠  Warning: Host network access requested                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  This mode allows the command to:                           │
│  • Connect to any network host                              │
│  • Potentially exfiltrate data                              │
│  • Access local network services                            │
│                                                             │
│  Consider safer alternatives:                               │
│  • --network allowlist --network-allow api.example.com:443  │
│                                                             │
╰─────────────────────────────────────────────────────────────╯

Continue with host network access? [y/N]:
```

### Runtime Unavailable Fallback

```bash
$ deputy exec --runtime gvisor -- ls

Runtime 'gvisor' is not available: runsc not found in PATH

Alternative runtimes available:
  1. docker (default) - Container isolation
  2. sandbox-exec     - macOS native (less isolation)
  3. none             - No isolation (dangerous)

[1] Use docker instead
[2] Use sandbox-exec instead
[3] Cancel

Choice [1]:
```

## Output Modes

### Default (Human-Readable)

```bash
$ deputy exec -- ls -la
total 24
drwxr-xr-x  5 user  staff   160 Jan 10 10:00 .
drwxr-xr-x  3 user  staff    96 Jan 10 09:00 ..
-rw-r--r--  1 user  staff  1234 Jan 10 10:00 main.go
-rw-r--r--  1 user  staff   567 Jan 10 10:00 go.mod
```

### JSON Events

```bash
$ deputy exec --json -- ls -la
{"event":"started","execution_id":"sandbox-abc123","runtime":"docker","timestamp":"2024-01-10T10:00:00Z"}
{"event":"output","execution_id":"sandbox-abc123","data":"total 24\n","stderr":false}
{"event":"output","execution_id":"sandbox-abc123","data":"drwxr-xr-x  5 user  staff   160 Jan 10 10:00 .\n","stderr":false}
{"event":"completed","execution_id":"sandbox-abc123","exit_code":0,"duration_ms":234}
```

### Verbose (Debug)

```bash
$ deputy exec --verbose -- ls -la
[sandbox] Using runtime: docker (version 24.0.5)
[sandbox] Workspace: /Users/you/project -> /workspace
[sandbox] Mode: workspace-write
[sandbox] Network: none
[sandbox] Image: alpine:latest
[sandbox] Filtered env vars: LD_PRELOAD, GITHUB_TOKEN
[sandbox] Starting container...
[sandbox] Container ID: abc123def456
total 24
drwxr-xr-x  5 user  staff   160 Jan 10 10:00 .
...
[sandbox] Exit code: 0
[sandbox] Duration: 234ms
[sandbox] Cleaning up container abc123def456
```

### Dry Run

```bash
$ deputy exec --dry-run --runtime docker --network allowlist --network-allow proxy.golang.org:443 -- go mod download
Would execute:

  Runtime: docker
  Image: golang:latest
  Command: ["go", "mod", "download"]

  Filesystem:
    Mode: workspace-write
    Workspace: /Users/you/project -> /workspace
    Working dir: /workspace

  Network:
    Mode: allowlist
    Allowed hosts:
      - proxy.golang.org:443

  Resource limits:
    Memory: 512m
    CPU: 1.0
    Max PIDs: 256
    Max files: 1024

  Security:
    Capabilities dropped: all except CHOWN, FOWNER, SETUID, SETGID, KILL
    Seccomp: default

  Docker command equivalent:
    docker run --rm \
      --network none \
      --read-only \
      --tmpfs /tmp \
      -v /Users/you/project:/workspace:rw \
      -w /workspace \
      --memory 512m \
      --cpus 1.0 \
      --pids-limit 256 \
      --cap-drop ALL \
      --cap-add CHOWN --cap-add FOWNER --cap-add SETUID --cap-add SETGID --cap-add KILL \
      --security-opt no-new-privileges \
      golang:latest \
      go mod download
```

## Shell Completion

```bash
# Bash
$ deputy exec --runtime <TAB>
docker  gvisor  none  sandbox-exec  plugin

$ deputy exec --mode <TAB>
read-only  workspace-write  full-access  network-isolated  ephemeral

$ deputy exec --network <TAB>
none  allowlist  bridge  host
```

## Error Messages

### Command Not Found

```
$ deputy exec -- nonexistent-command
Error: command 'nonexistent-command' not found in sandbox

The sandbox uses 'alpine:latest' which has a minimal set of tools.
For more tools, use a different image:
  deputy exec --image ubuntu:latest -- nonexistent-command
  deputy exec --image node:20 -- npm ...
  deputy exec --image golang:latest -- go ...
```

### Permission Denied

```
$ deputy exec --mode read-only -- touch newfile
Error: cannot write 'newfile': filesystem is read-only

Current mode: read-only
  - Can READ files in workspace
  - CANNOT write any files

To allow writes:
  deputy exec --mode workspace-write -- touch newfile
```

### Network Denied

```
$ deputy exec -- curl https://example.com
Error: network access denied

Current network mode: none
  - All network access is blocked

To allow network access:
  deputy exec --network allowlist --network-allow example.com:443 -- curl https://example.com
```

### Timeout

```
$ deputy exec --timeout 5s -- sleep 60
Error: execution timed out after 5s

The command was terminated because it exceeded the timeout.
To allow longer execution:
  deputy exec --timeout 2m -- sleep 60
```

## Integration with Other Commands

### Pipeline Usage

```bash
# Sandboxed analysis
deputy scan | deputy exec -- jq '.vulnerabilities[].id'

# Generate SBOM in sandbox
deputy exec -- cyclonedx-cli convert --input-file bom.json --output-file bom.xml

# Safe script execution
cat untrusted-script.sh | deputy exec --stdin - --mode read-only -- sh
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Build in sandbox
  run: deputy exec --timeout 10m -- make build

# GitLab CI
build:
  script:
    - deputy exec --runtime docker --network allowlist --network-allow registry.npmjs.org:443 -- npm ci
    - deputy exec --network none -- npm run build
```

### Proxy Integration

```bash
# Run package manager through proxy
deputy proxy go -- go mod download
# Equivalent to:
deputy exec --network allowlist --network-allow proxy.golang.org:443 -- go mod download

# The proxy command is a convenience wrapper
```

## Configuration File

```yaml
# .deputy.yaml
exec:
  # Default runtime
  default_runtime: docker

  # Default image for container runtimes
  default_image: alpine:latest

  # Default mode
  default_mode: workspace-write

  # Default network
  default_network: none

  # Default resource limits
  limits:
    memory: 512m
    cpu: "1.0"
    max_pids: 256
    timeout: 5m

  # Skip confirmation for these modes (use with caution)
  skip_confirmation: []

  # Presets for common workflows
  presets:
    build:
      mode: workspace-write
      network: none
      timeout: 10m

    download:
      mode: workspace-write
      network: allowlist
      network_allow:
        - "*.golang.org:443"
        - "registry.npmjs.org:443"
        - "pypi.org:443"

    analyze:
      mode: read-only
      network: none
      timeout: 5m
```

Usage with presets:

```bash
deputy exec --preset build -- make
deputy exec --preset download -- go mod download
deputy exec --preset analyze -- semgrep --config auto .
```
