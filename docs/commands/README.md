# Commands

Deputy is intentionally pipeline-friendly: commands compose well with each other and with tools like `jq`.

> **Tip**: `deputy <command> --help` for authoritative flag details.

## Command Overview

| Command | Purpose | Key Flags |
| --- | --- | --- |
| [`scan`](scan.md) | Find vulnerabilities via OSV | `--ref`, `--format`, `--policy`, `--ignore-unfixed` |
| [`fix`](fix.md) | Generate/apply remediation plans | `--apply`, `--report`, `--agent` |
| [`triage`](triage.md) | Prioritize findings | `--format`, `--agent` |
| [`diff`](diff.md) | Compare dependency changes between refs | `--skip-vuln-scan`, `--licenses` |
| [`sbom`](sbom.md) | Generate CycloneDX/SPDX SBOMs | `--format`, `--ref`, `--enrich-licenses` |
| [`list`](list.md) | Dump PURLs for scripting | `--format`, `--only-direct` |
| [`policy`](policy.md) | Lint, test, bundle, evaluate policies | subcommands: `lint`, `test`, `eval`, `bundle` |
| [`proxy`](proxy.md) | Run policy-enforcing package proxy | subcommands: `serve`, `template` |

## Quick Examples

```console
# Scan current repo
$ deputy scan

# Scan and output JSON for CI
$ deputy scan --format json --output scan.json

# Generate remediation commands
$ deputy fix

# Compare dependencies between branches
$ deputy diff main feature/upgrade

# Generate an SBOM
$ deputy sbom --format spdx-json --output sbom.spdx.json

# List all dependencies as PURLs
$ deputy list --format json | jq '.items[].purl'

# Validate policies before use
$ deputy policy lint policy/*.yaml
```

## Pipelines

Commands compose naturally:

```console
# Generate SBOM, then scan it
$ deputy sbom --format protobom-json | deputy scan sbom -

# Scan, then feed to fix
$ deputy scan --format json | deputy fix --report -

# List deps, filter with jq
$ deputy list --format json | jq '.items[] | select(.isDirect) | .purl'
```

## Exit Codes

- `0` — Success (no policy violations)
- `1` — Policy violations, scan errors, or other failures

Use exit codes for CI gating.

## Detailed Documentation

### Core Workflow

- [Scan](scan.md) — Vulnerability scanning
- [Fix](fix.md) — Remediation planning
- [Triage](triage.md) — Prioritization
- [Diff](diff.md) — Dependency change analysis
- [SBOM](sbom.md) — SBOM generation
- [List](list.md) — Dependency listing

### Enforcement & Platform

- [Policy](policy.md) — Policy authoring tools
- [Proxy](proxy.md) — Package proxy
