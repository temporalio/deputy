# `deputy mcp`

Run an MCP (Model Context Protocol) server to expose Deputy's vulnerability analysis capabilities to AI assistants like Claude, Codex, and other MCP-compatible tools.

## Synopsis

```
deputy mcp serve [flags]
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--transport` | `stdio` | Transport mode: `stdio` or `http` |
| `--address` | `127.0.0.1:8080` | Address to listen on for HTTP transport (for example, `127.0.0.1:8080` or `0.0.0.0:8080`) |
| `--auth-mode` | `disabled` | HTTP authentication mode: `disabled`, `optional`, or `required` |
| `--auth-jwks-url` | | JWKS endpoint URL, or OIDC issuer URL when `--auth-oidc-discovery` is set |
| `--auth-oidc-discovery` | `false` | Discover JWKS from the OIDC issuer URL |
| `--auth-issuers` | | Trusted JWT issuers for HTTP auth |
| `--auth-audiences` | | Expected JWT audiences for HTTP auth |
| `--auth-required-claims` | | Required JWT claims for HTTP auth |
| `--auth-clock-skew` | `0s` | Clock skew tolerance for token validation, maximum `5m` |
| `--allow-insecure` | `false` | Allow unauthenticated MCP HTTP on non-loopback addresses |

## What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) is an open standard that enables AI assistants to interact with external tools and data sources. Deputy's MCP server exposes vulnerability scanning, dependency analysis, and remediation capabilities as tools that AI assistants can invoke.

Every tool's input and output contract is defined in proto
([`deputy.mcp.v1`](../../api/deputy/mcp/v1/mcp.proto)): the advertised JSON
Schemas are derived from the proto descriptors, requests are validated against
the same rules the schemas advertise, and every result is validated against
its output schema before it is returned. Results omit zero values of plain
fields, so an absent field means empty, none, or not applicable (no
`vulnerabilities` key means none were found). Affirmative answers (`clean`,
`found`, `direct`, `hasFix`, `migration`, `executable`, `depth`,
`isContainerDiff`) are present whenever they apply, even when false or zero,
and severity count maps always carry all their keys so per-severity counts
sum to the total.

```mermaid
flowchart LR
    subgraph AI["AI Assistant"]
        Claude["Claude / Codex / etc."]
    end

    subgraph MCP["Deputy MCP Server"]
        direction TB
        Stdio["stdio transport"]
        HTTP["HTTP/SSE transport"]
        Tools["15 Security Tools"]
        Stdio --> Tools
        HTTP --> Tools
    end

    subgraph Deputy["Deputy Core"]
        OSV["OSV Database"]
        Scan["Scanner"]
        Graph["Dependency Graph"]
        SBOM["SBOM Generator"]
    end

    Claude <-->|"JSON-RPC"| Stdio
    Claude <-->|"SSE"| HTTP
    Tools --> OSV & Scan & Graph & SBOM

    classDef ai fill:#e3f2fd,stroke:#1565c0
    classDef mcp fill:#e8f5e9,stroke:#2e7d32
    classDef core fill:#f3e5f5,stroke:#7b1fa2
    classDef transport fill:#fff3e0,stroke:#e65100

    class Claude ai
    class Tools mcp
    class Stdio,HTTP transport
    class OSV,Scan,Graph,SBOM core
```

## Transport Modes

Deputy's MCP server supports two transport modes:

### stdio (default)

The stdio transport communicates over stdin/stdout using JSON-RPC. This is the standard mode for local integrations with desktop AI tools.

```bash
deputy mcp serve
```

**Best for:**
- Claude Desktop, Claude Code, Cursor, Zed, Windsurf
- Local development
- Single-user scenarios

### HTTP (SSE)

The HTTP transport runs a web server using Server-Sent Events (SSE) for communication. This mode is useful for remote access, shared servers, or web-based integrations.

```bash
deputy mcp serve --transport http
```

HTTP binds to `127.0.0.1:8080` by default. Non-loopback binds require JWT
authentication unless you intentionally pass `--allow-insecure`.

```bash
deputy mcp serve --transport http --address 0.0.0.0:8080 \
  --auth-mode required \
  --auth-jwks-url https://issuer.example.com/.well-known/jwks.json \
  --auth-issuers https://issuer.example.com \
  --auth-audiences deputy-mcp
```

**Best for:**
- Remote/shared servers
- Container deployments
- Web-based AI integrations
- Load-balanced setups

**Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | SSE endpoint for MCP sessions |
| `/mcp` | GET | Alternative SSE endpoint |
| `/health` | GET | Health check (returns JSON) |
| `/info` | GET | Server info and available tools |

**Health check example:**
```bash
curl http://localhost:8080/health
# {"service":"deputy-mcp","status":"healthy","version":"0.1.0"}
```

## Quick Start

### Claude Code (Anthropic)

The fastest way to add Deputy to Claude Code:

```bash
# Add Deputy MCP server (user scope - available across all projects)
claude mcp add --transport stdio deputy --scope user -- deputy mcp serve
```

Or using JSON configuration:

```bash
claude mcp add-json deputy '{"command":"deputy","args":["mcp","serve"]}'
```

**Verify it's working:**
```bash
claude mcp list
claude mcp get deputy
```

**Alternative: Edit config directly**

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

For project-specific configuration, add to `.mcp.json` in the project root.

### OpenAI Codex CLI

**Option 1: CLI command**
```bash
codex mcp add deputy -- deputy mcp serve
```

**Option 2: Edit `~/.codex/config.toml`**

```toml
[mcp_servers.deputy]
command = "deputy"
args = ["mcp", "serve"]
```

With environment variables for debug logging:

```toml
[mcp_servers.deputy]
command = "deputy"
args = ["mcp", "serve"]

[mcp_servers.deputy.env]
DEPUTY_LOG_LEVEL = "debug"
```

> [!NOTE]
> The CLI and VSCode Codex extension share this configuration.

### Claude Desktop

Add to your Claude Desktop configuration:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

**Restart Claude Desktop** after saving the configuration.

### VS Code (GitHub Copilot)

**Option 1: Via Command Palette**
1. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
2. Run `MCP: Add Server`
3. Choose "Stdio" transport
4. Enter `deputy` as the name
5. Enter `deputy mcp serve` as the command

**Option 2: Edit `.vscode/mcp.json`** (project-specific)

```json
{
  "servers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

**Option 3: Global configuration**

Run `MCP: Add Server`, then select "Global" to add to your user profile.

### Cursor

**Option 1: Project-specific** - Create `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

**Option 2: Global** - Create `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

**Option 3: Via Settings UI**
1. Open Settings (`Cmd+,` / `Ctrl+,`)
2. Search for "MCP"
3. Click "Edit in mcp.json"
4. Add the deputy configuration

### Zed

Add to Zed's settings (`~/.config/zed/settings.json`):

```json
{
  "context_servers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Windsurf

Add to Windsurf's MCP configuration:

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"]
    }
  }
}
```

### HTTP Transport (Remote/Shared Access)

For remote deployments or shared team servers, use HTTP transport with
required JWT authentication:

**Start the server:**
```bash
deputy mcp serve --transport http --address 0.0.0.0:8080 \
  --auth-mode required \
  --auth-jwks-url https://issuer.example.com/.well-known/jwks.json \
  --auth-issuers https://issuer.example.com \
  --auth-audiences deputy-mcp
```

**Claude Code (SSE):**
```bash
claude mcp add --transport sse deputy-remote http://your-server:8080
```

**VS Code (HTTP):**
```json
{
  "servers": {
    "deputy-remote": {
      "type": "sse",
      "url": "http://your-server:8080"
    }
  }
}
```

**Cursor (HTTP):**
```json
{
  "mcpServers": {
    "deputy-remote": {
      "url": "http://your-server:8080"
    }
  }
}
```

## Available Tools

Deputy's MCP server exposes 15 tools organized into categories:

### Server Metadata

| Tool | Description |
|------|-------------|
| `get_server_info` | Get Deputy MCP server build, process, and tool metadata |

Use `get_server_info` when checking that an MCP restart picked up a newly
installed local Deputy build. It reports the Deputy version, process ID, start
time, registered tools, and default exclude paths without exposing local
filesystem paths.

### Policy Discovery

| Tool | Description |
|------|-------------|
| `list_policy_entrypoints` | List policy entrypoints, categories, variables, and helpers for CEL policy authoring |

Use `list_policy_entrypoints` when writing or reviewing Deputy policies. It
reports each entrypoint's canonical category, description, helpers, and CEL
variables with explicit `required` flags so agents and humans know which
bindings need presence checks. Pass `category` to filter to `scan`, `proxy`,
`diff`, `container_diff`, `sbom`, `fix`, `triage`, `dockerfile`, `secrets`,
`graph`, `server`, or `sandbox`; legacy aliases `container` and `service` are
accepted, and `exec` maps to the canonical `sandbox` category.

### Vulnerability Analysis

| Tool | Description |
|------|-------------|
| `explain_vulnerability` | Get detailed information about a CVE or GHSA by ID |
| `explain_vulnerabilities` | Batch lookup for multiple vulnerability IDs |
| `scan_package` | Check a single package for known vulnerabilities |
| `scan_directory` | Scan a directory for vulnerabilities in all dependencies |
| `scan_container` | Scan a container image for vulnerabilities |
| `triage_vulnerabilities` | Prioritize vulnerabilities with actionable recommendations |

### Dependency Analysis

| Tool | Description |
|------|-------------|
| `list_dependencies` | List all dependencies in a directory with metadata |
| `analyze_dependency_graph` | Build and analyze the dependency graph |
| `graph_why` | Show why a package is in your dependencies (like `go mod why`) |
| `graph_needs` | Show what packages depend on a given package |

### Comparison

| Tool | Description |
|------|-------------|
| `diff_refs` | Compare dependencies between Git refs or container images |

### SBOM Generation

| Tool | Description |
|------|-------------|
| `generate_sbom` | Generate Software Bill of Materials (CycloneDX, SPDX, Protobom) |

### Remediation

| Tool | Description |
|------|-------------|
| `get_remediation` | Get actionable commands to fix vulnerabilities |

## Tool Reference

### `scan_package`

Check a single package version for known vulnerabilities.

**Input:**
```json
{
  "purl": "pkg:golang/golang.org/x/net@v0.17.0"
}
```

You can also provide split package fields:

```json
{
  "name": "golang.org/x/net",
  "version": "0.17.0",
  "ecosystem": "go"
}
```

Prefer `purl` when it comes from another Deputy MCP result such as
`list_dependencies`, `analyze_dependency_graph`, or `diff_refs`. Split fields
remain useful when the user names a package manually. Common ecosystem aliases
are accepted and normalized, such as `golang` to `go`, `python` to `pypi`,
`ruby` to `rubygems`, `java` to `maven`, and `GitHub Actions` to
`github-actions`.

Scan tools return compact vulnerability summaries so agents can make routing
decisions without loading full advisory prose into context. Use
`explain_vulnerability` or `explain_vulnerabilities` with the returned IDs when
you need full `details` text or complete advisory references.
The `severity` field is always a canonical label: `CRITICAL`, `HIGH`,
`MEDIUM`, `LOW`, or `UNKNOWN`; raw CVSS vectors remain internal scoring data
and are not emitted as the MCP severity value.
When present, `published` and `modified` use RFC3339 timestamps.
Vulnerability arrays are ordered consistently: higher severity first, then
direct dependencies, fixable findings, and stable package/ID tie-breakers.

**Output:**
```json
{
  "package": "golang.org/x/net",
  "version": "v0.17.0",
  "ecosystem": "go",
  "purl": "pkg:golang/golang.org/x/net@v0.17.0",
  "clean": false,
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "aliases": ["GO-2024-0001", "GHSA-abcd-efgh-ijkl"],
      "summary": "Example vulnerability",
      "severity": "CRITICAL",
      "fixedVersions": ["v0.17.1"],
      "packageFixes": [
        {
          "module": "golang.org/x/net",
          "ecosystem": "go",
          "fixedVersions": ["v0.17.1"]
        }
      ],
      "resolvedFix": {
        "status": "in_place",
        "version": "v0.17.1"
      },
      "references": ["https://example.com/advisory"],
      "referenceCount": 8,
      "referencesTruncated": true
    }
  ]
}
```

### `scan_directory`

Scan a local directory for vulnerabilities.

**Input:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "ecosystems": ["go", "npm"],
  "excludePaths": [".bin/**", "**/testdata"]
}
```

`excludePaths` uses the same directory-glob semantics as `--exclude-path` in
the CLI. Local source scans also prune directories ignored by `.gitignore`.
`deputy mcp serve` also inherits `scan.exclude_paths` from an auto-discovered
`.deputy.yaml`; tool-call `excludePaths` are unioned with those configured
defaults.
The source-oriented tools (`scan_directory`, `list_dependencies`,
`get_remediation`, `triage_vulnerabilities`, `generate_sbom`, `graph_why`,
`graph_needs`, `analyze_dependency_graph`, and Git `diff_refs`) accept this
field.
For Git repository paths, `scan_directory`, `list_dependencies`,
`get_remediation`, `triage_vulnerabilities`, `generate_sbom`, and graph tools
also accept optional `ref` to analyze a branch, tag, or commit. Git `diff_refs`
uses `baseRef` and `targetRef` instead.
Their MCP schemas require a non-empty local `path` before any scan, graph, SBOM,
or remediation work starts. Graph query tools also require a non-empty
`package`, and `analyze_dependency_graph.targetPurl` must start with `pkg:`
when provided.
When a tool scans a Git repository snapshot, results echo `ref`,
`effectiveRef`, and `commit` when Deputy's target resolver provides them.

**Output:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "effectiveRef": "HEAD~0",
  "commit": "abc123def456",
  "packagesScanned": 142,
  "clean": false,
  "vulnerabilitiesBySeverity": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "unknown": 0
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "summary": "Example vulnerability",
      "severity": "HIGH",
      "fixedVersions": ["1.2.4"],
      "references": ["https://example.com/advisory"]
    }
  ],
  "scanTime": "2.3s"
}
```

### `list_dependencies`

List dependencies discovered in a local directory. Use this when an agent needs
the exact package identities, PURLs, directness, and source locations before
calling graph, remediation, or vulnerability tools.

**Input:**
```json
{
  "path": "/path/to/project",
  "directOnly": true,
  "ref": "HEAD",
  "ecosystems": ["go", "npm"],
  "excludePaths": [".bin/**", "**/testdata"]
}
```

**Output:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "effectiveRef": "HEAD~0",
  "commit": "abc123def456",
  "total": 2,
  "direct": 2,
  "totalDiscovered": 142,
  "directDiscovered": 24,
  "transitiveDiscovered": 118,
  "dependencies": [
    {
      "name": "golang.org/x/net",
      "version": "v0.17.0",
      "ecosystem": "go",
      "purl": "pkg:golang/golang.org/x/net@v0.17.0",
      "direct": true,
      "locations": ["go.mod"],
      "manifestRefs": [
        {
          "path": "go.mod",
          "manager": "go",
          "groups": ["direct"]
        }
      ]
    }
  ]
}
```

`total`, `direct`, and `transitive` describe the returned `dependencies` array
after filters such as `directOnly`. `totalDiscovered`, `directDiscovered`, and
`transitiveDiscovered` describe the full discovered inventory after ecosystem
and exclude-path filters, but before the `directOnly` display filter. When
feeding another MCP tool, prefer `dependencies[].purl` over a short package
name because it preserves ecosystem and version identity. Dependency ecosystem
fields use Deputy's canonical lower-case names such as `go`, `npm`, and `pypi`.
`locations` is a compact list of files that referenced the dependency.
`manifestRefs` preserves structured source identity from Deputy's dependency
proto, including package manager, dependency groups, and `componentKey` when the
manifest key differs from the vulnerability package name, such as mise/asdf
tools remapped to another vulnerability ecosystem.
Dependencies are sorted by PURL, then directness, name, version, and ecosystem
for stable repeated agent calls.

### `scan_container`

Scan a container image for vulnerabilities.

**Input:**
```json
{
  "image": "nginx:1.25",
  "platform": "linux/amd64"
}
```

The MCP schema requires a non-empty `image` and rejects undeclared fields before
starting a scan.

Supports:
- Remote registries: `nginx:1.25`, `ghcr.io/owner/app:v1`
- Docker daemon: `docker-daemon://myapp:latest`
- Tarballs: `tarball:///tmp/image.tar`

### `get_server_info`

Get metadata for the running Deputy MCP server.

**Input:**
```json
{}
```

**Output:**
```json
{
  "name": "deputy",
  "version": "0.0.0-dev",
  "protocol": "mcp",
  "description": "Deputy MCP server for software supply chain security",
  "processId": 12345,
  "startedAt": "2026-07-01T16:00:00Z",
  "toolCount": 15,
  "tools": [
    "get_server_info",
    "list_policy_entrypoints",
    "explain_vulnerability",
    "explain_vulnerabilities",
    "scan_package",
    "scan_directory",
    "list_dependencies",
    "generate_sbom",
    "get_remediation",
    "analyze_dependency_graph",
    "graph_why",
    "graph_needs",
    "triage_vulnerabilities",
    "scan_container",
    "diff_refs"
  ]
}
```

The tool is useful for local agents that need to verify which MCP process is
currently serving requests after reinstalling or restarting Deputy.

### `explain_vulnerability`

Get detailed information about a vulnerability.

**Input:**
```json
{
  "id": "CVE-2021-44228",
  "referenceLimit": 20
}
```

**Output:**
```json
{
  "id": "CVE-2021-44228",
  "summary": "Remote code execution in Log4j",
  "details": "Apache Log4j2 2.0-beta9 through 2.15.0...",
  "severity": "CRITICAL",
  "fixedVersions": ["2.17.0", "2.12.3", "2.3.1"],
  "packageFixes": [
    {
      "module": "org.apache.logging.log4j:log4j-core",
      "ecosystem": "maven",
      "fixedVersions": ["2.17.0", "2.12.3", "2.3.1"]
    }
  ],
  "references": [...]
}
```

`referenceLimit` is optional. Omit it or pass a negative value to return all
references, pass `0` to omit references, or pass a positive value to cap the
returned list. When capped, `referenceCount` reports the full reference count
and `referencesTruncated` is `true`.

`fixedVersions` contains same-package version fixes from OSV package ranges.
`packageFixes` preserves package/module-specific fixes, including fixes that
require moving to a different module path. `resolvedFix`, when present, is
Deputy's installability-aware verdict with status `in_place`, `migration`,
`unavailable`, or `unverified`. OSV Git range commit markers are not reported
as package versions.

### `explain_vulnerabilities`

Get detailed information about multiple vulnerability IDs with partial-success
semantics.

**Input:**
```json
{
  "ids": ["CVE-2021-44228", "CVE-NONEXISTENT"],
  "referenceLimit": 20
}
```

**Output:**
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "summary": "Remote code execution in Log4j",
      "severity": "CRITICAL"
    }
  ],
  "errors": [
    "CVE-NONEXISTENT: vulnerability CVE-NONEXISTENT not found"
  ]
}
```

The output preserves the input order for found advisories. Missing vulnerability
IDs are reported as stable per-ID not-found strings instead of raw upstream OSV
HTTP response bodies. `referenceLimit` applies independently to each returned
vulnerability.

### `analyze_dependency_graph`

Build the dependency graph and optionally find dependency paths to a target
package PURL. `targetPurl` must be a valid PURL. The version may be omitted to
match the package identity regardless of resolved version.

For Git repositories, graph tools accept optional `ref` to analyze a branch, tag,
or commit snapshot. The graph build and vulnerability annotation use the same
ref.

**Input:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "targetPurl": "pkg:npm/lodash",
  "excludePaths": [".bin/**"],
  "resolveTransitives": false,
  "extended": false
}
```

By default graph tools use local manifests and lockfiles only. Set
`resolveTransitives` to `true` when you need more precise transitive edges from
package registry, deps.dev, or Git lookups; this is slower and may require
network access.

Set `extended` to `true` when you need graph metadata beyond local path
resolution. For Go projects, extended mode includes import status metadata such
as `required` and `declared` so agents can distinguish a disconnected module
that is still listed in `go.mod` from a package that is only present in the
broader module graph.

**Output:**
```json
{
  "path": "/path/to/project",
  "stats": {
    "totalNodes": 142,
    "directNodes": 24,
    "transitiveNodes": 118,
    "maxConnectedDepth": 4,
    "disconnectedNodes": 3
  },
  "target": {
    "query": "pkg:npm/lodash",
    "found": true,
    "pathCount": 1,
    "matchedPurls": ["pkg:npm/lodash@4.17.21"],
    "matchedNodes": [
      {
        "name": "lodash",
        "version": "4.17.21",
        "ecosystem": "npm",
        "purl": "pkg:npm/lodash@4.17.21",
        "direct": false,
        "depth": 2
      }
    ],
    "message": "1 dependency path to target found"
  },
  "pathsToTarget": [
    {
      "nodes": ["express@4.18.2", "body-parser@1.20.2", "lodash@4.17.21"],
      "nodeDetails": [
        {
          "name": "express",
          "version": "4.18.2",
          "ecosystem": "npm",
          "purl": "pkg:npm/express@4.18.2",
          "direct": true,
          "depth": 0
        },
        {
          "name": "body-parser",
          "version": "1.20.2",
          "ecosystem": "npm",
          "purl": "pkg:npm/body-parser@1.20.2",
          "direct": false,
          "depth": 1
        },
        {
          "name": "lodash",
          "version": "4.17.21",
          "ecosystem": "npm",
          "purl": "pkg:npm/lodash@4.17.21",
          "direct": false,
          "depth": 2
        }
      ],
      "depth": 2
    }
  ]
}
```

Graph path `nodes` are display labels kept for readability. Prefer
`nodeDetails[].purl` when feeding a dependency into another MCP tool because it
preserves package identity, ecosystem, directness, graph depth, disconnected
status, and extended-mode import status.

Direct dependencies are returned as one-node, zero-hop paths. This keeps the
`paths[].nodeDetails[]` shape consistent for direct and transitive matches.
`vulnerablePaths` is capped at 50 returned examples; use
`vulnerablePathCount` and `vulnerablePathsTruncated` to tell whether the array
is complete. `pathsToTarget` is capped at 20 returned examples; use
`target.pathCount` and `pathsToTargetTruncated` for the full target-path count.
When `targetPurl` is provided, the `target` object reports whether the package
identity was found and how many paths were resolved. A missing `pathsToTarget`
with `target.found=false` means the package was absent from the graph; a
missing `pathsToTarget` with `target.found=true` means the package was
present but no path from a direct/root dependency was resolved. In that case, inspect
`target.matchedNodes[]` for exact PURL, graph depth, disconnected status, and
extended-mode import status.

### `graph_why`

Trace why a package is in your dependency graph.

`package` accepts a package name, `name@version`, or a PURL from
`list_dependencies`. Exact PURL matches are preferred when multiple packages
share a short name.

**Input:**
```json
{
  "path": "/path/to/project",
  "package": "pkg:npm/lodash@4.17.21",
  "ref": "HEAD",
  "showAll": false,
  "excludePaths": [".bin/**"],
  "resolveTransitives": false,
  "extended": false
}
```

**Output:**
```json
{
  "package": "lodash",
  "found": true,
  "direct": false,
  "matchedNode": {
    "name": "lodash",
    "version": "4.17.21",
    "ecosystem": "npm",
    "purl": "pkg:npm/lodash@4.17.21",
    "direct": false,
    "depth": 2
  },
  "paths": [
    {
      "nodes": ["express@4.18.2", "body-parser@1.20.2", "lodash@4.17.21"],
      "nodeDetails": [
        {
          "name": "express",
          "version": "4.18.2",
          "ecosystem": "npm",
          "purl": "pkg:npm/express@4.18.2",
          "direct": true,
          "depth": 0
        },
        {
          "name": "body-parser",
          "version": "1.20.2",
          "ecosystem": "npm",
          "purl": "pkg:npm/body-parser@1.20.2",
          "direct": false,
          "depth": 1
        },
        {
          "name": "lodash",
          "version": "4.17.21",
          "ecosystem": "npm",
          "purl": "pkg:npm/lodash@4.17.21",
          "direct": false,
          "depth": 2
        }
      ],
      "depth": 2
    }
  ],
  "pathCount": 1,
  "message": "1 dependency path found"
}
```

`paths` is capped at 10 returned examples by default. Set `showAll: true` to
return up to 100 paths. Use `pathCount` and `pathsTruncated` to detect when the
returned array is a sample rather than the complete path set.

When `found=true` and `pathCount=0`, `matchedNode` still describes the package
that matched the query. Use `matchedNode.disconnected` and
`matchedNode.importStatus` to decide whether to retry with
`resolveTransitives: true`, retry with `extended: true`, inspect native
ecosystem tooling, or treat the package as a direct/root dependency with no
reverse path to explain.

### `graph_needs`

Find packages that depend on a given package (reverse lookup).

`package` accepts the same query forms as `graph_why`: package name,
`name@version`, or PURL.

**Input:**
```json
{
  "path": "/path/to/project",
  "package": "lodash@4.17.21",
  "ref": "HEAD",
  "excludePaths": [".bin/**"],
  "resolveTransitives": false,
  "extended": false
}
```

**Output:**
```json
{
  "package": "lodash",
  "found": true,
  "direct": false,
  "dependents": [
    {
      "name": "body-parser",
      "version": "1.20.2",
      "ecosystem": "npm",
      "purl": "pkg:npm/body-parser@1.20.2",
      "direct": false
    },
    {
      "name": "express",
      "version": "4.18.2",
      "ecosystem": "npm",
      "purl": "pkg:npm/express@4.18.2",
      "direct": true
    }
  ],
  "directCount": 1,
  "transitiveCount": 1
}
```

When a package is not found, or when it is found but no dependents are resolved,
`message` explains the not-found result, direct/root dependency, disconnected
inventory item, or graph that may need `resolveTransitives: true`.
Dependents are sorted with direct packages first, then by package name and PURL
for stable agent consumption.

### `triage_vulnerabilities`

Get prioritized vulnerability list with recommendations.

**Input:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "excludePaths": [".bin/**"]
}
```

**Output:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "effectiveRef": "HEAD~0",
  "commit": "abc123def456",
  "totalVulnerabilities": 11,
  "criticalCount": 1,
  "highCount": 3,
  "mediumCount": 2,
  "lowCount": 2,
  "unknownCount": 3,
  "fixableCount": 8,
  "migrationCount": 1,
  "unfixableCount": 3,
  "directVulnerabilities": 4,
  "transitiveVulnerabilities": 7,
  "directFixableCount": 2,
  "transitiveFixableCount": 6,
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "package": "log4j-core",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "severity": "CRITICAL",
      "priority": "critical",
      "priorityReason": "Critical severity, fixable, in direct dependency",
      "hasFix": true,
      "fixedVersions": ["2.17.0"],
      "resolvedFix": {
        "status": "in_place",
        "version": "2.17.0"
      }
    }
  ],
  "recommendations": [
    "Address 1 critical vulnerability(ies) immediately",
    "Update or migrate direct dependencies to fix 2 vulnerability(ies)",
    "Plan package or module migrations for 1 vulnerability(ies)"
  ]
}
```

Use `vulnerabilities[].purl` with `graph_why`, `graph_needs`, or
`scan_package` when following up on triaged findings; it preserves package
ecosystem and version identity. Severity totals include `unknownCount`, so the
severity count fields add up to `totalVulnerabilities`. `fixableCount`,
`directVulnerabilities`, and `transitiveVulnerabilities` are independent totals.
Use `directFixableCount` to decide whether direct dependency updates or
migrations are available, and `transitiveFixableCount` to decide whether
follow-up graph/importer analysis is needed for fixable transitive
vulnerabilities. `priorityReason` includes direct/transitive context when a fix
is available.

### `generate_sbom`

Generate a Software Bill of Materials.

**Input:**
```json
{
  "path": "/path/to/project",
  "format": "cyclonedx-json",
  "ref": "v1.0.0",
  "enrichLicenses": true,
  "excludePaths": [".bin/**"]
}
```

Supported formats: `cyclonedx-json`, `spdx-json`, `protobom-json`. The MCP
schema rejects other `format` values before generation starts.

### `diff_refs`

Compare dependencies between Git refs or container images.

Use `path` for Git ref diffs. Container image diffs are selected from
`baseRef` and `targetRef`; omit `path` for image comparisons. Both refs must be
the same kind: either Git refs or container image refs. Common branch names such
as `main`, `master`, `develop`, and `HEAD` are treated as Git refs and require a
repository `path`.

**Input (Git refs):**
```json
{
  "path": "/path/to/repo",
  "baseRef": "v1.0.0",
  "targetRef": "v2.0.0",
  "excludePaths": [".bin/**"]
}
```

**Input (Container images):**
```json
{
  "baseRef": "nginx:1.24",
  "targetRef": "nginx:1.25",
  "platform": "linux/amd64"
}
```

**Output (Git ref diff):**
```json
{
  "path": "/path/to/repo",
  "baseRef": "v1.0.0",
  "targetRef": "v2.0.0",
  "baseCommit": "abc123def456",
  "targetCommit": "789abc012def",
  "isContainerDiff": false,
  "changes": [
    {
      "name": "lodash",
      "baseVersion": "4.17.20",
      "targetVersion": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "changeType": "upgraded",
      "direct": true,
      "ecosystem": "npm"
    }
  ],
  "updatedCount": 1,
  "vulnerabilities": [...],
  "vulnerabilitiesBySeverity": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "unknown": 0
  }
}
```

Container image diffs additionally report `vulnerabilityChanges` with delta
semantics (`added`, `removed`, `fixed`, `persisted`) and a `containerSummary`
of image-specific package, vulnerability, layer, and config changes:

```json
{
  "vulnerabilityChanges": [
    {
      "id": "CVE-2024-1234",
      "changeType": "fixed",
      "severity": "HIGH",
      "package": "openssl",
      "ecosystem": "deb",
      "baseVersion": "3.0.0",
      "targetVersion": "3.0.2",
      "fixedVersions": ["3.0.2"]
    }
  ],
  "containerSummary": {
    "packagesAdded": 2,
    "packagesRemoved": 1,
    "packagesUpgraded": 8,
    "vulnerabilitiesRemoved": 1,
    "vulnerabilitiesFixed": 3
  }
}
```

`changes[].purl` is included when Deputy has a Package URL so agents can
distinguish packages that share the same display name. `vulnerabilities` and
`vulnerabilitiesBySeverity` describe the target ref or image after advisory
alias consolidation.
`platform` applies only to container image diffs and is forwarded to both image
scans so multi-architecture tags compare the intended image variant.
Dependency changes are sorted with direct packages first, then by change type,
ecosystem, package name, PURL, and versions for stable repeated agent calls.

### `get_remediation`

Scan a directory and get a remediation plan for its findings. The result is
the agent-facing projection of a `deputy.remediation.v1` plan, generated by
the same `RemediationService.GeneratePlan` producer the API and agent flows
use.

**Input:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "excludePaths": [".bin/**"]
}
```

**Output:**
```json
{
  "path": "/path/to/project",
  "ref": "HEAD",
  "effectiveRef": "HEAD~0",
  "commit": "abc123def456",
  "planId": "8b6f1a52-6d5f-4a1e-9c7d-2f9d1c0e4b6a",
  "generatedAt": "2026-07-06T15:04:05Z",
  "vulnerabilitiesFound": 5,
  "stats": {
    "totalSteps": 1,
    "executableSteps": 1,
    "vulnerabilitiesAddressed": 4,
    "vulnerabilitiesUnaddressed": 1,
    "affectedPackages": 1,
    "affectedManagers": ["go"]
  },
  "steps": [
    {
      "id": "step-1",
      "kind": "version_upgrade",
      "title": "Update go dependency",
      "package": "github.com/example/pkg",
      "version": "v1.2.3",
      "purl": "pkg:golang/github.com/example/pkg@v1.2.3",
      "targetVersion": "v1.2.4",
      "migration": false,
      "manager": "go",
      "manifestPath": "go.mod",
      "command": "go get github.com/example/pkg@v1.2.4",
      "hint": "run go mod tidy after updating",
      "direct": true,
      "executable": true,
      "riskLevel": "medium",
      "affectedVulnerabilities": ["CVE-2026-1234", "GHSA-xxxx-xxxx-xxxx"]
    }
  ],
  "unfixableVulnerabilities": ["CVE-2026-9999"]
}
```

`stats.vulnerabilitiesAddressed` counts findings the plan fixes: verified
in-place fixes, migration fixes, and unverified advisory-claimed fixes that
Deputy can still turn into a step. `stats.vulnerabilitiesUnaddressed` and
`unfixableVulnerabilities` list what remains vulnerable; unaddressed means
still vulnerable, not safe. Step counts describe the deduplicated plan: they
can be lower than the addressed count when several findings share one package
upgrade or migration, and each step's `affectedVulnerabilities` links the
finding IDs it remediates. A `version_upgrade` step with `executable: false`
is upgrade guidance that needs a manual change, such as a module migration
(`migration: true` with `targetModule`). Steps include package identity so
agents can follow up with `graph_why` using the emitted `purl` or `package`
instead of parsing command text; for indirect migrations, set
`resolveTransitives` to `true` on the follow-up `graph_why` call when you
need the direct importer path.

## Example Conversations

### "Scan my project for vulnerabilities"

The AI assistant will use `scan_directory` with your project path and present the findings in a readable format.

### "Why do I have lodash in my dependencies?"

The AI assistant will use `graph_why` to trace the dependency path from your direct dependencies to lodash.

### "What would break if I removed express?"

The AI assistant will use `graph_needs` to find all packages that depend on express.

### "Compare security between our staging and production images"

The AI assistant will use `diff_refs` to compare two container images and highlight vulnerability differences.

### "Help me fix the critical vulnerabilities"

The AI assistant will use `triage_vulnerabilities` to prioritize issues, then `get_remediation` to generate fix commands.

## Environment Variables

Deputy's MCP server respects standard Deputy environment variables:

| Variable | Description |
|----------|-------------|
| `DEPUTY_LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error` |
| `DEPUTY_LOG_FORMAT` | Log format: `text`, `json` |
| `GITHUB_TOKEN` | GitHub token for private repos and rate limits |
| `DEPUTY_OTEL_ENABLED` | Enable OpenTelemetry tracing |

## Observability

The MCP server includes full OpenTelemetry instrumentation:

- **Traces**: Each tool invocation creates a span (`deputy.mcp.<tool_name>`)
- **Metrics**: Tool call counts, durations, and error rates
- **Logs**: Structured logging with tool context

Enable with:
```bash
export DEPUTY_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
deputy mcp serve
```

## Troubleshooting

### Server not starting

1. Verify Deputy is installed: `deputy version`
2. Check the path is correct: `which deputy`
3. Try running manually: `deputy mcp serve`

### Tools not appearing

1. Restart the AI assistant after configuration changes
2. Check logs for connection errors
3. Verify JSON configuration syntax

### Slow responses

1. First scan downloads OSV database (one-time)
2. Large projects take longer to scan
3. Container scans require image pulls

### Authentication errors (container scanning)

1. Verify Docker credentials: `docker login`
2. Check `~/.docker/config.json` exists
3. For private registries, ensure credentials are configured

### Debug mode

Enable debug logging to diagnose issues:

```json
{
  "mcpServers": {
    "deputy": {
      "command": "deputy",
      "args": ["mcp", "serve"],
      "env": {
        "DEPUTY_LOG_LEVEL": "debug"
      }
    }
  }
}
```

## Docker Deployment

Run Deputy MCP server in a container with HTTP transport:

```dockerfile
FROM golang:1.26 AS builder
RUN go install github.com/temporalio/deputy@latest

FROM gcr.io/distroless/base-debian12
COPY --from=builder /go/bin/deputy /deputy
EXPOSE 8080
ENTRYPOINT ["/deputy"]
CMD ["mcp", "serve", "--transport", "http", "--address", "0.0.0.0:8080", "--auth-mode", "required", "--auth-jwks-url", "https://issuer.example.com/.well-known/jwks.json"]
```

Or use docker-compose:

```yaml
services:
  deputy-mcp:
    image: ghcr.io/temporalio/deputy:latest
    command:
      - mcp
      - serve
      - --transport
      - http
      - --address
      - 0.0.0.0:8080
      - --auth-mode
      - required
      - --auth-jwks-url
      - https://issuer.example.com/.well-known/jwks.json
    ports:
      - "8080:8080"
```

Distroless images do not include `curl`; configure container health checks in
your orchestrator or probe `http://localhost:8080/health` from outside the
container.

## Production Deployment

When deploying the MCP server for production use (especially with HTTP transport), consider the following:

### Server Configuration

The HTTP server is configured with production-grade defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| Read Timeout | 30s | Maximum time to read request headers and body |
| Write Timeout | 0 (disabled) | Disabled for SSE long-polling connections |
| Idle Timeout | 120s | Keep-alive connection timeout |
| Header Timeout | 10s | Maximum time to read request headers |
| Max Header Size | 1MB | Maximum size of request headers |
| Shutdown Timeout | 30s | Graceful shutdown wait time |

### Tool Timeouts

Each tool category has configurable timeouts to prevent runaway operations:

| Category | Default | Tools |
|----------|---------|-------|
| Default | 30s | `explain_vulnerability`, `explain_vulnerabilities`, `scan_package` |
| Scan | 5m | `scan_directory`, `scan_container`, `list_dependencies`, `get_remediation`, `triage_vulnerabilities`, `diff_refs` |
| Graph | 2m | `analyze_dependency_graph`, `graph_why`, `graph_needs` |
| SBOM | 3m | `generate_sbom` |

### Panic Recovery

The HTTP handler includes automatic panic recovery that:
- Logs panics with full context (method, path, remote address)
- Returns a 500 Internal Server Error to the client
- Prevents server crashes from propagating to other requests

### Recommended Production Setup

For production HTTP deployments:

1. **Use a reverse proxy** (nginx, Caddy, Traefik) for:
   - TLS termination
   - Rate limiting
   - Request logging
   - Optional external authentication/authorization

2. **Require authentication when serving shared HTTP MCP**:
   ```bash
   deputy mcp serve --transport http --address 0.0.0.0:8080 \
     --auth-mode required \
     --auth-jwks-url https://issuer.example.com/.well-known/jwks.json \
     --auth-issuers https://issuer.example.com \
     --auth-audiences deputy-mcp
   ```

3. **Configure healthchecks**:
   ```bash
   curl http://localhost:8080/health
   # {"service":"deputy-mcp","status":"healthy","version":"..."}
   ```

4. **Enable observability**:
   ```bash
   export DEPUTY_OTEL_ENABLED=true
   export OTEL_EXPORTER_OTLP_ENDPOINT=your-collector:4317
   deputy mcp serve --transport http --address 0.0.0.0:8080 \
     --auth-mode required \
     --auth-jwks-url https://issuer.example.com/.well-known/jwks.json
   ```

5. **Kubernetes deployment example**:
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: deputy-mcp
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: deputy-mcp
     template:
       metadata:
         labels:
           app: deputy-mcp
       spec:
         containers:
         - name: deputy
           image: ghcr.io/temporalio/deputy:latest
           args:
           - mcp
           - serve
           - --transport
           - http
           - --address
           - 0.0.0.0:8080
           - --auth-mode
           - required
           - --auth-jwks-url
           - https://issuer.example.com/.well-known/jwks.json
           ports:
           - containerPort: 8080
           livenessProbe:
             httpGet:
               path: /health
               port: 8080
             initialDelaySeconds: 5
             periodSeconds: 10
           readinessProbe:
             httpGet:
               path: /health
               port: 8080
             initialDelaySeconds: 5
             periodSeconds: 5
           resources:
             requests:
               memory: "256Mi"
               cpu: "250m"
             limits:
               memory: "1Gi"
               cpu: "1000m"
   ```

### JWT Authentication

The MCP HTTP server supports JWT-based authentication for production deployments. The CLI supports JWKS and OIDC discovery; the Go API also supports inline static public keys for development or air-gapped environments.

**Authentication Modes:**

| Mode | Description |
|------|-------------|
| `disabled` | No authentication (default) |
| `optional` | Validates tokens if present, allows anonymous |
| `required` | Rejects requests without valid tokens |

**Configuration via CLI:**

```bash
deputy mcp serve --transport http --address 0.0.0.0:8080 \
  --auth-mode required \
  --auth-jwks-url https://issuer.example.com/.well-known/jwks.json \
  --auth-issuers https://issuer.example.com \
  --auth-audiences deputy-mcp \
  --auth-required-claims sub
```

Use OIDC discovery when you have the issuer URL rather than the JWKS endpoint:

```bash
deputy mcp serve --transport http --address 0.0.0.0:8080 \
  --auth-mode required \
  --auth-jwks-url https://issuer.example.com \
  --auth-oidc-discovery \
  --auth-issuers https://issuer.example.com \
  --auth-audiences deputy-mcp
```

**Configuration via Go API:**

```go
import (
    "github.com/temporalio/deputy/internal/mcp"
)

cfg := mcp.HTTPConfig{
    // ... other settings ...
    Auth: &mcp.AuthConfig{
        Mode: "required",
        JWKS: &mcp.JWKSConfig{
            URL:           "https://auth.example.com/.well-known/jwks.json",
            OIDCDiscovery: true,  // Auto-discover from issuer URL
            RefreshInterval: time.Hour,
        },
        Issuers:        []string{"https://auth.example.com"},
        Audiences:      []string{"deputy-mcp"},
        RequiredClaims: []string{"sub"},
        ClockSkew:      30 * time.Second,
    },
}

server := mcp.NewServer()
server.RunHTTPWithConfig(ctx, "0.0.0.0:8080", cfg)
```

**Static Keys (Development/Testing):**

For development or air-gapped environments:

```go
Auth: &mcp.AuthConfig{
    Mode: "required",
    StaticKeys: []mcp.StaticKeyConfig{{
        KeyID:     "dev-key-1",
        Algorithm: "ES256",
        PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----`,
    }},
}
```

**HTTP Headers:**

Request (client sends):
```
Authorization: Bearer <jwt-token>
```

Response (on auth failure):
```
WWW-Authenticate: Bearer realm="deputy-mcp"
X-MCP-Auth-Error: <error-code>
X-MCP-Auth-Message: <human-readable message>
```

**Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `missing_token` | 401 | No Authorization header (mode=required) |
| `invalid_token` | 401 | Malformed JWT |
| `expired_token` | 401 | Token past expiration |
| `signature_invalid` | 401 | Signature verification failed |
| `key_not_found` | 401 | Key ID not in JWKS or static keys |
| `invalid_issuer` | 403 | Issuer not in allowed list |
| `invalid_audience` | 403 | Audience not in allowed list |
| `missing_claim` | 403 | Required claim not present |

**Supported Algorithms:**

- RSA: RS256, RS384, RS512, PS256, PS384, PS512
- ECDSA: ES256, ES384, ES512
- EdDSA: Ed25519

**Security Notes:**

- Symmetric algorithms (HS256, etc.) are intentionally not supported - they require shared secrets which is insecure for distributed systems
- Clock skew tolerance: default is 0, maximum allowed is 5 minutes
- Always use HTTPS in production to protect tokens in transit
- Use JWKS with automatic refresh for key rotation support

## Security Considerations

- The MCP server runs with the same permissions as the user
- MCP tools are advertised as read-only and non-destructive. Tools that may
  consult advisory services, package registries, container registries, or other
  external sources are marked with `openWorldHint=true`; local dependency
  listing is marked closed-world.
- Local-source tools are restricted to source-tree-style paths: they reject
  remote URLs, network/UNC paths, `..` traversal, filesystem root scans, common
  Unix/macOS/Windows system directories, and common credential directories such
  as `.ssh`, `.aws`, and `.kube`
- Container scanning uses local Docker credentials
- **stdio transport**: No network services are exposed
- **HTTP transport**: Binds to specified address; use TLS, firewall rules, and authentication for production deployments
- **Panic recovery**: The server recovers from panics gracefully but you should monitor for panic logs

## Limitations

- **Streaming**: Large SBOM outputs are returned as complete responses
- **Caching**: Each tool invocation is independent (no session state)
- **Rate limiting**: Not built-in; use a reverse proxy for rate limiting

## See Also

- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Scan command](scan.md) — CLI equivalent
- [Graph command](graph.md) — CLI graph analysis
- [SBOM command](sbom.md) — CLI SBOM generation

## Platform Documentation

Official MCP configuration guides for each platform:

| Platform | Documentation |
|----------|---------------|
| Claude Code | [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp) |
| OpenAI Codex | [Model Context Protocol](https://developers.openai.com/codex/mcp/) |
| VS Code | [Use MCP servers in VS Code](https://code.visualstudio.com/docs/copilot/customization/mcp-servers) |
| Cursor | [Model Context Protocol (MCP)](https://cursor.com/docs/context/mcp) |
| MCP Spec | [Build an MCP server](https://modelcontextprotocol.io/docs/develop/build-server) |

## Code Pointers

- MCP Server: [`internal/mcp/server.go`](../../internal/mcp/server.go)
- CLI Command: [`internal/cli/cmd/mcp.go`](../../internal/cli/cmd/mcp.go)
- Documentation: [`internal/mcp/doc.go`](../../internal/mcp/doc.go)
