# Commands

Deputy is intentionally pipeline-friendly: commands compose well with each other and with tools like `jq`.

> [!TIP]
> `deputy <command> --help` for authoritative flag details.

## Command Overview

| Command | Purpose | Key Flags |
| --- | --- | --- |
| [`scan`](scan.md) | Find vulnerabilities via OSV | `--ref`, `--format`, `--policy`, `--with-graph`, `--secrets` |
| [`secrets`](secrets.md) | Scan for leaked secrets | `--format`, `--verify`, `--history`, `--diff`, `--deep` |
| [`explain`](explain.md) | Explain vulnerabilities in detail | `--agent`, `--enrich`, `--format` |
| [`fix`](fix.md) | Generate/apply remediation plans | `--apply`, `--report`, `--agent` |
| [`triage`](triage.md) | Prioritize findings | `--format`, `--agent` |
| [`diff`](diff.md) | Compare dependency changes between refs | `--skip-vuln-scan`, `--licenses` |
| [`graph`](graph.md) | Visualize dependency graph | `--format`, `--depth`, `--focus`, subcommands: `why`, `needs` |
| [`sbom`](sbom.md) | Generate CycloneDX/SPDX SBOMs | `--format`, `--ref`, `--enrich-licenses` |
| [`list`](list.md) | Dump PURLs for scripting | `--format`, `--direct`, `--source`, `--platform` |
| [`pin`](pin.md) | Pin dependencies to immutable refs | `--ecosystems`, `--exclude`, `--dry-run`, subcommands: `check`, `verify`, `update` |
| [`exec`](exec.md) | Run a command in a sandboxed runtime | `--runtime`, `--mode`, `--network`, `--exec-allow` |
| [`policy`](policy.md) | Lint, test, bundle, evaluate policies | subcommands: `lint`, `test`, `eval`, `bundle` |
| [`proxy`](proxy.md) | Run policy-enforcing package proxy | subcommands: `serve`, `template` |
| [`server`](server.md) | Run Deputy API server | `--addr`, `--public`, `--insecure`, `--egress-allow-*` |
| [`mcp`](mcp.md) | MCP server for AI assistants | subcommands: `serve` |
| [`init`](init.md) | Bootstrap Deputy in a project | `--force`, `--config-only`, `--policy-only` |
| [`config`](config.md) | Manage configuration files | subcommands: `validate`, `show`, `path` |

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

# Pin all dependencies to immutable refs
$ deputy pin

# Visualize dependency graph
$ deputy graph --format dot | dot -Tpng -o deps.png

# Why is a package in my deps?
$ deputy graph why lodash

# List all dependencies as PURLs
$ deputy list --format json | jq '.packages[].purl'

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
$ deputy list --format json | jq '.packages[] | select(.direct) | .purl'
```

## Exit Codes

- `0`: Success (no policy violations)
- `1`: Policy violations, scan errors, or other failures

Use exit codes for CI gating.

## Detailed Documentation

### Core Workflow

- [Scan](scan.md): Vulnerability scanning
- [Secrets](secrets.md): Secret and credential detection
- [Explain](explain.md): Vulnerability explanation with agent analysis
- [Fix](fix.md): Remediation planning
- [Triage](triage.md): Prioritization
- [Diff](diff.md): Dependency change analysis
- [Graph](graph.md): Dependency graph visualization
- [SBOM](sbom.md): SBOM generation
- [List](list.md): Dependency listing
- [Pin](pin.md): Dependency pinning for supply chain security
- [Exec](exec.md): Sandboxed command execution

### Enforcement & Platform

- [Policy](policy.md): Policy authoring tools
- [Proxy](proxy.md): Package proxy
- [Server](server.md): API server for remote clients

### Integrations

- [MCP](mcp.md): MCP server for AI assistants (Claude, Codex, Cursor)

### Setup & Configuration

- [Init](init.md): Project initialization
- [Config](config.md): Configuration management
- [Completion](completion.md): Shell autocompletion
