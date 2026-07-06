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
Triage Summary: /path/to/repo @ main

  Unique vulns: 5   Critical/High: 3   Fix available: 3

Top Impacted Packages (2 of 2):
  Severity shown per package = highest vuln severity in that package.
  1. CRITICAL github.com/example/pkg v1.2.3 (3 vulns: 1 CRIT, 2 HIGH) ↑ v1.2.4
  2. MEDIUM   github.com/other/dep v2.0.0 (2 vulns: 2 MED)
```

### JSON Format

JSON output marshals the `deputy.triage.v1.TriageResponse` proto with
snake_case field names, the same message the API returns:

```json
{
  "target": {
    "display_path": "/path/to/repo",
    "ref": "main",
    "effective_ref": "refs/heads/main",
    "commit_hash": "abc123def456"
  },
  "stats": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "unique": 5,
    "fix_available": 3
  },
  "top_packages": [
    {
      "package": "github.com/example/pkg",
      "version": "v1.2.3",
      "severity": "CRITICAL",
      "priority": "critical",
      "priority_reason": "critical severity with a fix available",
      "fix_version": "v1.2.4",
      "is_direct": true,
      "sample_ids": ["CVE-2026-1234"],
      "vulnerability_count": 3,
      "severity_counts": {"critical": 1, "high": 2}
    }
  ],
  "packages_with_vulns": 2,
  "generated_at": "2026-07-06T10:30:00Z"
}
```

`severity` is the package's highest finding severity, normalized to the
canonical CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN labels; `severity_counts` keys are
lowercase severity levels. `priority` and `priority_reason` come from the
canonical triage ladder (severity + fixability + directness) shared with the
MCP `triage_vulnerabilities` tool: a critical finding with no available fix
ranks below a fixable one, and the reason says why. Packages are ordered by
that ladder, so CLI, API, and MCP triage give the same remediation verdict
and the same ordering for the same findings.

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
