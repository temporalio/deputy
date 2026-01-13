# `deputy exec`

Run a command inside a sandboxed runtime and stream its output.

`deputy exec` is intended for local workflows and policy-driven automation. It
supports container runtimes (Docker, gVisor) and a macOS-only sandbox-exec
runtime for best-effort isolation.

## Synopsis

```
deputy exec -- <command> [args...]
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--runtime` | `docker` | Sandbox runtime: `docker`, `gvisor`, `none`, `sandbox-exec`, `plugin` |
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

## macOS `sandbox-exec` limitations

The `sandbox-exec` runtime is **deprecated by Apple** and provides best-effort
isolation only.

- No network allowlists (only `none` or full network).
- No additional mounts, hidden paths, or read-only path rules.
- No resource limits (memory/CPU/PIDs).
- Use `--exec-allow` to run binaries outside the default exec allowlist.

Prefer container runtimes when possible.

## Examples

```console
# Run a read-only command in the default runtime
$ deputy exec --mode read-only -- ls -la

# Run with Docker using a specific image
$ deputy exec --runtime docker --image alpine:3.19 -- echo hello

# macOS sandbox-exec (deprecated, best-effort)
$ deputy exec --runtime sandbox-exec --mode read-only -- ls -la

# macOS sandbox-exec with explicit exec allowlist
$ deputy exec --runtime sandbox-exec --mode read-only --exec-allow deputy -- deputy list
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded |
| `1` | Command failed or sandbox error |
| `124` | Command timed out (when `--timeout` is set) |

## See Also

- [Fix command](fix.md) — Uses sandboxed execution for AI agents
- [Sandbox policies](../reference/policy-inputs.md#sandbox-entrypoints) — CEL policies for sandbox control
- [Agents guide](../guides/agents.md) — AI-assisted workflows with sandboxing

## Code Pointers

- CLI: [`internal/cli/cmd/exec.go`](../../internal/cli/cmd/exec.go)
- Sandbox: [`internal/sandbox`](../../internal/sandbox)
