# `deputy triage`

Summarize and prioritize vulnerability findings with optional AI assistance.

## Synopsis

```
deputy triage [repo] [flags]
```

## When to Use

- A repo has many findings and you need a "top risks" view
- You want structured summaries for dashboards or audits
- You want AI-assisted analysis and recommendations

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--report` | | | Path to JSON scan report (use `-` for stdin) |
| `--ref` | | auto | Git reference to scan; omitted lets Deputy choose `HEAD` or the working tree |
| `--ecosystems` | | all | Limit to specific ecosystems |
| `--ignore-unfixed` | | `false` | Hide vulns without fixes |
| `--published-before` | | | Date filter for vulnerabilities |
| `--published-after` | | | Date filter for vulnerabilities |
| `--as-of` | | | Historical view date |
| `--format` | `-f` | `text` | Output format: `text`, `json` |
| `--policy` | | | CEL policy files (repeatable) |
| `--show-db-info` | | `false` | Show database metadata |

### Agent Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--agent` | | | AI agent (e.g., `codex`) |
| `--agent-model` | | | Model identifier |
| `--agent-sandbox` | | `read-only` | Sandbox policy |
| `--agent-full-auto` | | `false` | Full-auto mode |
| `--agent-thread` | | | Resume previous thread |
| `--agent-include-plan-tool` | | `true` | Allow plan tool |
| `--agent-skip-git-check` | | `true` | Skip git checks |

## Examples

### Basic Usage

```console
# Triage current repository
$ deputy triage

# Triage a remote repository
$ deputy triage github.com/hashicorp/vagrant --ref main
```

### Filtering

```console
# Only actionable vulnerabilities
$ deputy triage --ignore-unfixed

# Historical view
$ deputy triage --as-of 2024-12-31
```

### From Existing Report

```console
# Use a scan report
$ deputy triage --report scan.json

# Pipe from scan
$ deputy scan --format json | deputy triage --report -
```

### Output Formats

```console
# JSON for dashboards
$ deputy triage --format json > triage.json
```

### AI Assistance

```console
# Ask AI to prioritize and explain
$ deputy triage --agent codex

# With specific model
$ deputy triage --agent codex --agent-model gpt-4

# Resume a previous session
$ deputy triage --agent codex --agent-thread <thread-id>
```

## Output

### Text Format

```
Triage Summary for /path/to/repo @ HEAD

Top Affected Packages:
  1. github.com/example/pkg (3 vulns: 1 critical, 2 high)
  2. github.com/other/dep (2 vulns: 2 medium)

Severity Distribution:
  Critical: 1
  High: 2
  Medium: 2
  Low: 0

Recommendations:
  • Address github.com/example/pkg first (critical severity)
  • 3 of 5 vulnerabilities have available fixes
```

### JSON Format

```json
{
  "target": "/path/to/repo",
  "ref": "HEAD",
  "generated": "2025-01-15T10:30:00Z",
  "clusters": [
    {
      "package": "github.com/example/pkg",
      "version": "v1.2.3",
      "vulnerabilities": [...],
      "severity": "critical",
      "fixable": true
    }
  ],
  "stats": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0,
    "fixable": 3
  }
}
```

Each package summary also carries `priority` and `priority_reason`, computed by
the canonical triage ladder (severity + fixability + directness) shared with
the MCP `triage_vulnerabilities` tool — a critical finding with no available
fix ranks below a fixable one, and the reason says why. CLI, API, and MCP
triage therefore give the same remediation verdict for the same finding.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Errors or policy violations |

## See Also

- [Agents guide](../guides/agents.md)
- [Scan command](scan.md)

## Code Pointers

- CLI: [`internal/cli/cmd/triage.go`](../../internal/cli/cmd/triage.go)
- Analysis: [`internal/analysis`](../../internal/analysis)
