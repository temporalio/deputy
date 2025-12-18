# `deputy fix`

Generate and optionally apply remediation plans for vulnerabilities.

## Synopsis

```
deputy fix [repo] [flags]
```

## When to Use

- You want upgrade commands for fixable vulnerabilities
- You want a JSON plan for review/approval workflows
- You want to delegate complex fixes to an AI agent

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--report` | | | Path to JSON scan report (use `-` for stdin) |
| `--plan` | | | Path to existing remediation plan JSON |
| `--ref` | | `HEAD` | Git reference to scan |
| `--ecosystems` | | all | Limit to specific ecosystems |
| `--ignore-unfixed` | | `false` | Skip vulns without fixes |
| `--published-before` | | | Date filter for vulnerabilities |
| `--published-after` | | | Date filter for vulnerabilities |
| `--as-of` | | | Historical view date |
| `--format` | `-f` | `text` | Output format: `text`, `json` |
| `--apply` | | `false` | Execute remediation commands |
| `--policy` | | | CEL policy files (repeatable) |

### Agent Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--agent` | | AI agent to use (e.g., `codex`) |
| `--agent-model` | | Model identifier |
| `--agent-sandbox` | `workspace-write` | Sandbox: `read-only`, `workspace-write`, `danger-full-access` |
| `--agent-full-auto` | `false` | Enable full-auto mode (dangerous) |
| `--agent-thread` | | Resume a previous thread ID |
| `--agent-include-plan-tool` | `true` | Allow agent to use plan tool |
| `--agent-skip-git-check` | `true` | Skip git repository checks |

## Workflow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Scan      │ ──► │    Plan      │ ──► │    Apply     │
│  (or report) │     │  (commands)  │     │  (execute)   │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Examples

### Basic Usage

```console
# Scan and generate a plan
$ deputy fix

# Scan and immediately apply fixes
$ deputy fix --apply .
```

### Plan Management

```console
# Generate a JSON plan for review
$ deputy fix --format json > plan.json

# Review the plan, then apply it later
$ deputy fix --plan plan.json --apply .
```

### From Existing Scan Report

```console
# Use a scan report from CI
$ deputy scan --format json --output scan.json
$ deputy fix --report scan.json

# Pipe directly
$ deputy scan --format json | deputy fix --report -
```

### Filtering

```console
# Only generate commands for fixable vulns
$ deputy fix --ignore-unfixed

# Only Go ecosystem
$ deputy fix --ecosystems go
```

### AI Agent Assistance

```console
# Use Codex agent
$ deputy fix --agent codex

# With specific model
$ deputy fix --agent codex --agent-model gpt-4

# Read-only analysis (safest)
$ deputy fix --agent codex --agent-sandbox read-only

# Full-auto mode (use with caution!)
$ deputy fix --agent codex --agent-full-auto
```

## Output

### Text Format

```
Remediation Plan:
  Target: /path/to/repo
  Commit: abc123d...

  • Upgrade Go toolchain to v1.24.9
  • Apply dependency upgrades (4 total, 4 runnable)
       go.mod:
         › go get github.com/example/pkg@v1.2.4
         › go get github.com/other/dep@v2.0.0
         ↻ go mod tidy
```

### JSON Format

```json
{
  "target": {
    "repo": "/path/to/repo",
    "ref": "HEAD",
    "commit": "abc123d..."
  },
  "stdlibUpgrade": "v1.24.9",
  "commands": [
    {
      "ecosystem": "go",
      "command": "go get github.com/example/pkg@v1.2.4",
      "workdir": ".",
      "runnable": true
    }
  ],
  "stats": {
    "totalCommands": 4,
    "runnableCommands": 4
  }
}
```

## Supported Ecosystems

| Ecosystem | Command Pattern |
| --- | --- |
| Go | `go get <module>@<version>` |
| npm | `npm install <package>@<version>` |
| PyPI | `pip install <package>==<version>` |
| RubyGems | `bundle update <gem>` |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Errors or policy violations |

## See Also

- Agent safety: [`docs/guides/agents.md`](../guides/agents.md)
- Pipeline example: [`docs/examples/pipeline.md`](../examples/pipeline.md)

## Code Pointers

- CLI: [`internal/cli/cmd/fix.go`](../../internal/cli/cmd/fix.go)
- Remediation logic: [`internal/remediation`](../../internal/remediation)
