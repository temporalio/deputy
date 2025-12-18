# Deputy Cheat Sheet

Quick reference for common commands and patterns.

## Core Commands

| Command | Purpose | Example |
| --- | --- | --- |
| `scan` | Find vulnerabilities | `deputy scan` |
| `fix` | Generate/apply upgrades | `deputy fix --apply` |
| `diff` | Compare dependencies | `deputy diff main HEAD` |
| `sbom` | Generate SBOM | `deputy sbom -o sbom.json` |
| `list` | List dependencies | `deputy list --format json` |
| `triage` | Prioritize findings | `deputy triage` |
| `proxy` | Enforce at download | `deputy proxy go -- go get ...` |
| `policy` | Develop CEL policies | `deputy policy lint *.yaml` |

## Common Flags

| Flag | Commands | Description |
| --- | --- | --- |
| `--format json` | scan, diff, fix, list | JSON output for scripting |
| `--output FILE` | scan, sbom, list | Write to file |
| `--ref REF` | scan, sbom, list, diff | Git reference |
| `--policy FILE` | scan, diff, proxy | Apply CEL policy |
| `--ignore-unfixed` | scan, diff | Hide vulns without fixes |
| `--only-direct` | list | Direct dependencies only |
| `--apply` | fix | Execute remediation steps |
| `--ecosystems` | scan, list | Limit to specific ecosystems |

## Quick Recipes

```bash
# Scan current directory
deputy scan

# Scan with JSON output
deputy scan --format json | jq '.summary'

# Compare branches
deputy diff main feature-branch

# What changed this week?
deputy diff "HEAD@{1.week.ago}" HEAD

# Generate CycloneDX SBOM
deputy sbom --format cyclonedx-json -o sbom.json

# Count dependencies
deputy list --format json | jq '.count'

# Auto-fix vulnerabilities
deputy fix --apply

# Download with policy enforcement
deputy proxy go -- go get github.com/example/pkg

# Lint policies
deputy policy lint policy/*.yaml
```

## Output Formats

| Command | Formats |
| --- | --- |
| `scan` | `text`, `json` |
| `diff` | `text`, `json` |
| `fix` | `text`, `json` |
| `list` | `text`, `tsv`, `json` |
| `sbom` | `cyclonedx-json`, `spdx-json`, `protobom-json` |
| `triage` | `text`, `json` |

## Git References

```bash
# Compare tags
deputy diff v1.0.0 v2.0.0

# Working tree (uncommitted changes)
deputy diff main WORKING
deputy diff main .

# Time-based
deputy diff "HEAD@{yesterday}" HEAD
deputy diff "main@{1.month.ago}" main
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error or policy denial |

## Environment Variables

```bash
# Logging
export DEPUTY_LOG_LEVEL=debug
export DEPUTY_LOG_FORMAT=json

# GitHub (for rate limits)
export GITHUB_TOKEN=ghp_...

# Agent APIs
export ANTHROPIC_API_KEY=sk-...
```

## Policy Quick Start

```yaml
# deny-critical.yaml
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.severity == "CRITICAL")
        reason: critical vulnerability found
```

```bash
# Lint
deputy policy lint deny-critical.yaml

# Use with scan
deputy scan --policy deny-critical.yaml
```

## See Also

- Full docs: [`docs/README.md`](README.md)
- Commands: [`docs/commands/`](commands/)
- Guides: [`docs/guides/`](guides/)
