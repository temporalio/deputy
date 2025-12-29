# Architecture

Deputy is a Go CLI that composes core subsystems: inventory, analysis, remediation, policy, and proxy. This document explains how the pieces fit together.

## High-Level Architecture

```mermaid
flowchart TB
  subgraph Entry["Entry Point"]
    Main[main.go]
    CLI[internal/cli]
  end

  subgraph Commands["Command Layer"]
    CMD[internal/cli/cmd]
  end

  subgraph Core["Core Packages"]
    Inv[internal/inventory]
    Analysis[internal/analysis]
    Remed[internal/remediation]
    SBOM[internal/sbom]
    Policy[internal/policy]
    Proxy[internal/proxy]
  end

  subgraph Support["Support Packages"]
    Git[internal/gitutil]
    PURL[internal/purlx]
    Out[internal/output]
    Config[internal/config]
  end

  subgraph External["External Services"]
    OSV[(OSV API)]
    DepsD[(deps.dev)]
    GH[(GitHub API)]
  end

  Main --> CLI
  CLI --> CMD
  CMD --> Inv & Analysis & Remed & SBOM & Policy & Proxy
  Inv --> PURL & Git
  Analysis --> OSV
  SBOM --> DepsD & GH
  Policy --> Analysis

  style Entry fill:#e3f2fd,stroke:#1565c0
  style Commands fill:#fff3e0,stroke:#e65100
  style Core fill:#e8f5e9,stroke:#2e7d32
  style Support fill:#f3e5f5,stroke:#7b1fa2
  style External fill:#fff9c4,stroke:#f9a825
```

## Design Principles

### One Inventory Model

All commands share the same inventory extraction logic. Whether scanning, diffing, generating SBOMs, or running the proxy, Deputy uses `internal/inventory` to parse manifests into a normalized package list.

```mermaid
flowchart TB
  Manifests["go.mod<br/>package.json<br/>requirements.txt<br/>Gemfile"]
  Inv["internal/inventory"]
  Packages["Package list<br/>(PURLs)"]
  Scan["scan"]
  SBOM["sbom"]
  Diff["diff"]
  Proxy["proxy"]

  Manifests --> Inv --> Packages
  Packages --> Scan
  Packages --> SBOM
  Packages --> Diff
  Packages --> Proxy

  classDef source fill:#e3f2fd,stroke:#1565c0
  classDef process fill:#e8f5e9,stroke:#2e7d32
  classDef output fill:#f3e5f5,stroke:#7b1fa2

  class Manifests source
  class Inv,Scan,SBOM,Diff,Proxy process
  class Packages output
```

### Non-Destructive Git Operations

Deputy never modifies the working tree for read operations. Instead, it uses `go-git` to:

- Clone repositories to temp directories
- Resolve refs to commit SHAs
- Read files at specific commits without checkout
- Generate diffs between refs

Only `fix --apply` modifies files, and only when explicitly requested.

### Policy as Control Plane

CEL policies are evaluated at multiple points, not just scan output:

```mermaid
flowchart LR
  subgraph Entrypoints["Entrypoints"]
    direction TB
    ScanEntry["scan_report"]
    ProxyEntry["proxy_*_request"]
    SBOMEntry["sbom_component"]
  end

  Engine["CEL Policy Engine"]

  subgraph Actions["Decisions"]
    direction TB
    ScanActions["allow | warn | deny"]
    ProxyActions["allow | warn | deny"]
    SBOMActions["allow | warn | deny"]
  end

  ScanEntry --> Engine
  ProxyEntry --> Engine
  SBOMEntry --> Engine
  Engine --> ScanActions
  Engine --> ProxyActions
  Engine --> SBOMActions

  classDef source fill:#e3f2fd,stroke:#1565c0
  classDef control fill:#fff3e0,stroke:#e65100
  classDef output fill:#f3e5f5,stroke:#7b1fa2

  class ScanEntry,ProxyEntry,SBOMEntry source
  class Engine control
  class ScanActions,ProxyActions,SBOMActions output
```

This lets you write rules once and enforce them everywhere: in CI scans, at package download time, and during SBOM generation.

### Pipeline-Friendly I/O

- **stdout**: Command output (scan results, SBOMs, lists)
- **stderr**: Logs and diagnostics
- **JSON formats**: Stable schemas for scripting
- **Exit codes**: 0 = success, 1 = error/policy violation

### Domain vs Integration Split

Deputy keeps pure domain logic separate from service integrations:

- `internal/vuln` owns the vulnerability domain model, CVSS/severity parsing,
  alias consolidation, and fix selection. It is pure and has no IO.
- `internal/analysis/osv` owns OSV API and GitHub Actions bucket integration,
  including cache-aware lookups and conversion into domain types.
- `internal/license` handles license enrichment (deps.dev, registry APIs, local
  scans) and uses `internal/diskcache` for on-disk caching.
- `internal/analysis` is a thin orchestration layer and compatibility facade
  that keeps CLI and policy code stable while delegating to the above packages.

## Package Reference

### Entry Points

| Package | Purpose |
|---------|---------|
| `main.go` | Binary entry point |
| `internal/cli` | CLI initialization, root command, logging setup |
| `internal/cli/cmd` | Individual Cobra commands (scan, fix, diff, etc.) |

### Core Packages

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `internal/inventory` | Dependency detection from manifests | `Package`, `Inventory`, `Extractor` |
| `internal/inventory/manifests` | Manifest/manager heuristics for locations | `DetectManager`, `InferArtifactManager` |
| `internal/analysis` | Orchestration + facades over vuln/OSV integrations | `OSVClient`, `Vulnerability` (aliases) |
| `internal/analysis/osv` | OSV API + GitHub Actions bucket integration | `OSVClient`, `PkgInput` |
| `internal/vuln` | Domain types, CVSS/severity, consolidation | `Vulnerability`, `ConsolidatedVulnerability` |
| `internal/license` | License enrichment and scanning | `DepsClient` |
| `internal/remediation` | Fix planning, upgrade commands | `Plan`, `Step`, `Upgrade` |
| `internal/report` | Report/context assembly helpers (rendering in subpackages) | `ManifestContext`, `Summary`, `TriageReport`, `PolicyFinding`, `Target` |
| `internal/report/render` | Human-readable report rendering | `RenderVulnerabilityList`, `TriageSummaryDoc`, `RenderPolicyFindings` |
| `internal/sbom` | SBOM generation (CycloneDX, SPDX) | `Generator`, `Document` |
| `internal/policy` | CEL evaluation engine | `Evaluator`, `Policy`, `Action` |
| `internal/proxy` | Package proxy adapters and server | `Server`, `Adapter`, `Request` |

### Support Packages

| Package | Purpose |
|---------|---------|
| `internal/gitutil` | Git operations via go-git |
| `internal/purlx` | PURL parsing and normalization |
| `internal/output` | Output formatting (table, JSON) |
| `internal/config` | Configuration loading |
| `internal/diskcache` | JSON-on-disk cache helpers |
| `internal/cli/flags` | Shared CLI flag parsing helpers |

## Data Flow

### Scan Command

```mermaid
sequenceDiagram
    participant User
    participant CLI as scan.go
    participant Inv as inventory
    participant OSV as analysis
    participant Pol as policy
    participant Out as output

    User->>CLI: deputy scan
    CLI->>Inv: Extract(target, ref)
    Inv-->>CLI: []Package
    CLI->>OSV: Query(packages)
    OSV-->>CLI: []Vulnerability
    CLI->>Pol: Evaluate(vulns, policy)
    Pol-->>CLI: []Action (allow/deny/warn)
    CLI->>Out: Render(results)
    Out-->>User: Table/JSON output
```

### Proxy Request

```mermaid
sequenceDiagram
    participant Client as go/npm/pip
    participant Proxy as deputy proxy
    participant Adapter as ecosystem adapter
    participant Policy as policy engine
    participant Upstream as registry

    Client->>Proxy: GET /pkg@version
    Proxy->>Adapter: Normalize(request)
    Adapter-->>Proxy: ArtifactRequest
    Proxy->>Policy: Evaluate(request, vulns)
    Policy-->>Proxy: allow/deny
    alt allowed
        Proxy->>Upstream: Fetch artifact
        Upstream-->>Proxy: artifact bytes
        Proxy-->>Client: 200 + artifact
    else denied
        Proxy-->>Client: 403 + reason
    end
```

### Proxy Authentication (JWT/OIDC)

When authentication is enabled, the proxy validates JWT tokens before policy evaluation:

```mermaid
sequenceDiagram
    participant Client as go/npm/pip
    participant Auth as auth middleware
    participant JWKS as JWKS cache
    participant Policy as policy engine
    participant Upstream as registry

    Client->>Auth: GET /pkg (+ Bearer token)

    alt no token + mode=required
        Auth-->>Client: 401 missing_token
    else has token
        Auth->>Auth: Parse JWT header (kid, alg)
        Auth->>JWKS: GetKey(kid)

        alt key not found
            JWKS->>JWKS: ForceRefresh()
        end

        JWKS-->>Auth: public key
        Auth->>Auth: Verify signature

        alt invalid signature
            Auth-->>Client: 401 signature_invalid
        else valid
            Auth->>Auth: Validate claims (exp, iss, aud)

            alt claims invalid
                Auth-->>Client: 401/403 + error code
            else claims valid
                Auth->>Policy: Evaluate(request, jwt claims)
                Policy-->>Auth: allow/deny

                alt allowed
                    Auth->>Upstream: Fetch artifact
                    Upstream-->>Auth: artifact
                    Auth-->>Client: 200 + artifact
                else denied by policy
                    Auth-->>Client: 403 + policy reason
                end
            end
        end
    end
```

**JWT claims available in CEL policies:**

| Field | Type | Description |
|-------|------|-------------|
| `jwt.sub` | string | Subject (user/service ID) |
| `jwt.iss` | string | Issuer URL |
| `jwt.aud` | list | Audience(s) |
| `jwt.exp` | int | Expiration timestamp |
| `jwt.anonymous` | bool | True if no token (mode=optional) |
| `jwt.<custom>` | any | Custom claims from token |

See the [proxy command reference](../commands/proxy.md#authentication-jwtoidc) for configuration details.

## Key Abstractions

### Package (internal/inventory)

Represents a dependency with ecosystem-agnostic metadata:

```go
type Package struct {
    Name      string   // e.g., "github.com/gin-gonic/gin"
    Version   string   // e.g., "v1.9.1"
    Ecosystem string   // e.g., "go", "npm", "pypi"
    PURL      string   // Package URL
    Direct    bool     // Direct vs transitive
    Licenses  []string // SPDX identifiers
    Source    string   // Manifest file path
}
```

### Vulnerability (internal/analysis)

OSV-aligned vulnerability record:

```go
type Vulnerability struct {
    ID            string   // CVE, GHSA, etc.
    Aliases       []string // Alternative IDs
    Summary       string   // Brief description
    Severity      string   // CRITICAL, HIGH, MEDIUM, LOW
    Published     time.Time
    FixedVersions []string // Versions with fix
    Package       Package  // Affected package
}
```

### Policy Action (internal/policy)

Result of CEL evaluation:

```go
type Action struct {
    Type        string            // "allow", "warn", "deny"
    Reason      string            // Human-readable explanation
    Policy      string            // Policy name that triggered
    Headers     map[string]string // For proxy responses
    Remediation string            // Suggested fix
}
```

## Extension Points

### Adding a New Ecosystem

1. **Inventory**: Create extractor in `internal/inventory/`
2. **PURL**: Register type in `internal/purlx/`
3. **Proxy**: Add adapter in `internal/proxy/`
4. **Tests**: Add fixtures in `testdata/`

### Adding a Policy Entrypoint

1. Define constant in `internal/policy/entrypoints.go`
2. Add input bindings in `internal/policy/evaluator.go`
3. Document in the [policy framework](../reference/policy-framework.md)
4. Add example in `policy/examples/`

### Adding a Command

1. Create `internal/cli/cmd/yourcommand.go`
2. Register in `internal/cli/cmd/register.go`
3. Document in `docs/commands/`

## External Dependencies

| Dependency | Purpose |
|------------|---------|
| [OSV API](https://osv.dev) | Vulnerability data |
| [deps.dev](https://deps.dev) | License and dependency info |
| [GitHub API](https://docs.github.com) | Repo metadata, rate limits |
| [go-git](https://github.com/go-git/go-git) | Git operations |
| [OSV-SCALIBR](https://github.com/google/osv-scalibr) | Manifest parsing |
| [Protobom](https://github.com/protobom/protobom) | SBOM handling |
| [CEL-Go](https://github.com/google/cel-go) | Policy evaluation |

## Code Pointers

| What | Where |
|------|-------|
| CLI entry | [main.go](../../main.go) |
| Root command | [internal/cli/cli.go](../../internal/cli/cli.go) |
| Command registration | [internal/cli/cmd/register.go](../../internal/cli/cmd/register.go) |
| Scan implementation | [internal/cli/cmd/scan.go](../../internal/cli/cmd/scan.go) |
| Fix implementation | [internal/cli/cmd/fix.go](../../internal/cli/cmd/fix.go) |
| Policy evaluator | [internal/policy/evaluator.go](../../internal/policy/evaluator.go) |
| Policy entrypoints | [internal/policy/entrypoints.go](../../internal/policy/entrypoints.go) |
| OSV client | [internal/analysis/osv/client.go](../../internal/analysis/osv/client.go) |
| Inventory extraction | [internal/inventory/inventory.go](../../internal/inventory/inventory.go) |
| Go proxy adapter | [internal/proxy/gomod.go](../../internal/proxy/gomod.go) |
| npm proxy adapter | [internal/proxy/npm.go](../../internal/proxy/npm.go) |

## See Also

- [Contributing](contributing.md) - Development workflow
- [AGENTS context](../../AGENTS.md) - Project context for AI agents
- [Policy framework](../reference/policy-framework.md) - Policy framework design
- [Proxy design](../reference/proxy.md) - Proxy architecture
