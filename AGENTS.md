# AGENTS.md

Deputy is a Go CLI for software supply chain security. Scan, fix, diff, and enforce policies.

## Architecture Overview

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#4f46e5', 'primaryTextColor': '#fff', 'primaryBorderColor': '#3730a3', 'lineColor': '#6366f1', 'secondaryColor': '#f0fdf4', 'tertiaryColor': '#fefce8', 'background': '#ffffff', 'mainBkg': '#ffffff', 'secondBkg': '#f8fafc', 'border1': '#e2e8f0', 'border2': '#cbd5e1', 'fontFamily': 'ui-sans-serif, system-ui, sans-serif'}}}%%

flowchart TB
    subgraph CLI["<b>CLI Layer</b>"]
        direction LR
        main["<b>main.go</b>"] --> cli["<b>cli.go</b>"] --> register["<b>register.go</b>"]
    end

    subgraph Commands["<b>Commands</b>"]
        direction LR
        scan["🔍 <b>scan</b>"]
        fix["🔧 <b>fix</b>"]
        diff["📊 <b>diff</b>"]
        sbom["📦 <b>sbom</b>"]
        list["📋 <b>list</b>"]
        policy["📜 <b>policy</b>"]
        proxy["🛡️ <b>proxy</b>"]
    end

    subgraph Core["<b>Core Packages</b>"]
        direction TB
        
        subgraph Row1[" "]
            direction LR
            inventory["<b>inventory/</b><br/>OSV-SCALIBR<br/>PURL parsing<br/>lockfile detection"]
            analysis["<b>analysis/</b><br/>OSV client<br/>CVSS scoring<br/>severity mapping"]
            policy_pkg["<b>policy/</b><br/>CEL engine<br/>entrypoints<br/>variable bindings"]
        end
        
        subgraph Row2[" "]
            direction LR
            remediation["<b>remediation/</b><br/>fix planning<br/>version bumps<br/>AI agents"]
            gitutil["<b>gitutil/</b><br/>go-git clone<br/>ref resolution<br/>commit diffs"]
            sbom_pkg["<b>sbom/</b><br/>Protobom<br/>CycloneDX<br/>SPDX"]
        end
    end

    subgraph External["<b>External Services</b>"]
        direction LR
        osv_db[("<b>OSV Database</b><br/>vulnerability data")]
        depsdev[("<b>Deps.dev</b><br/>licenses & deps")]
        github[("<b>GitHub API</b><br/>repo metadata")]
    end

    register --> Commands
    
    scan & diff --> inventory & analysis & gitutil & policy_pkg
    fix --> inventory & analysis & remediation & policy_pkg
    sbom --> inventory & sbom_pkg
    list --> inventory
    policy --> policy_pkg
    proxy --> policy_pkg & inventory

    analysis --> osv_db
    inventory --> depsdev
    sbom_pkg & gitutil --> github

    style CLI fill:#4f46e5,stroke:#3730a3,color:#fff
    style Commands fill:#8b5cf6,stroke:#6d28d9,color:#fff
    style Core fill:#f0fdf4,stroke:#86efac,color:#166534
    style External fill:#fefce8,stroke:#fde047,color:#854d0e
    
    style main fill:#6366f1,stroke:#4338ca,color:#fff
    style cli fill:#6366f1,stroke:#4338ca,color:#fff
    style register fill:#6366f1,stroke:#4338ca,color:#fff
    
    style scan fill:#a78bfa,stroke:#7c3aed,color:#fff
    style fix fill:#a78bfa,stroke:#7c3aed,color:#fff
    style diff fill:#a78bfa,stroke:#7c3aed,color:#fff
    style sbom fill:#a78bfa,stroke:#7c3aed,color:#fff
    style list fill:#a78bfa,stroke:#7c3aed,color:#fff
    style policy fill:#a78bfa,stroke:#7c3aed,color:#fff
    style proxy fill:#a78bfa,stroke:#7c3aed,color:#fff
    
    style inventory fill:#dcfce7,stroke:#22c55e,color:#166534
    style analysis fill:#dcfce7,stroke:#22c55e,color:#166534
    style policy_pkg fill:#dcfce7,stroke:#22c55e,color:#166534
    style remediation fill:#dcfce7,stroke:#22c55e,color:#166534
    style gitutil fill:#dcfce7,stroke:#22c55e,color:#166534
    style sbom_pkg fill:#dcfce7,stroke:#22c55e,color:#166534
    
    style osv_db fill:#fef9c3,stroke:#eab308,color:#854d0e
    style depsdev fill:#fef9c3,stroke:#eab308,color:#854d0e
    style github fill:#fef9c3,stroke:#eab308,color:#854d0e
    
    style Row1 fill:transparent,stroke:transparent
    style Row2 fill:transparent,stroke:transparent
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#4f46e5', 'primaryTextColor': '#fff', 'lineColor': '#6366f1', 'fontFamily': 'ui-sans-serif, system-ui, sans-serif'}}}%%

flowchart LR
    subgraph Developer["<b>Developer</b>"]
        direction TB
        cmd["<tt>go get</tt> / <tt>npm install</tt>"]
    end

    subgraph Proxy["<b>Deputy Proxy</b>"]
        direction TB
        intercept["Intercept Request"]
        eval["⚡ Policy Evaluation<br/><i>CEL engine</i>"]
        intercept --> eval
    end

    subgraph Upstream["<b>Upstream Registry</b>"]
        direction TB
        registry["proxy.golang.org<br/>registry.npmjs.org"]
    end

    cmd -->|"① request"| intercept
    eval -->|"② check policy"| decision{allow?}
    decision -->|"✓ yes"| registry
    registry -->|"③ fetch"| Proxy
    Proxy -->|"④ response"| cmd
    decision -->|"✗ no"| blocked["⛔ blocked"]
    blocked -->|"④ deny"| cmd

    style Developer fill:#dbeafe,stroke:#3b82f6,color:#1e40af
    style Proxy fill:#f0fdf4,stroke:#22c55e,color:#166534
    style Upstream fill:#fefce8,stroke:#eab308,color:#854d0e
    
    style cmd fill:#60a5fa,stroke:#2563eb,color:#fff
    style intercept fill:#86efac,stroke:#22c55e,color:#166534
    style eval fill:#4ade80,stroke:#16a34a,color:#fff
    style registry fill:#fde047,stroke:#ca8a04,color:#854d0e
    style decision fill:#c4b5fd,stroke:#7c3aed,color:#5b21b6
    style blocked fill:#fca5a5,stroke:#dc2626,color:#991b1b
```

**Data Flow (for `scan` command):**
1. **Target resolution** — local directory, `git` ref, or remote repository.
2. **Inventory extraction** — OSV-SCALIBR parses lockfiles into PURLs.
3. **Vulnerability lookup** — query OSV API or local GCS bucket mirror.
4. **Policy evaluation** — CEL engine runs per-vulnerability and report-level rules.
5. **Output rendering** — table, JSON, or SARIF format.

## Quick Reference

```bash
go test ./...                                  # run all tests
go test -v -run TestName ./internal/pkg/...   # run specific test
go build -o deputy .                           # build binary
./deputy scan                                  # test locally
```

## Commands

```bash
# Vulnerability scanning
deputy scan                                    # scan current directory
deputy scan github.com/owner/repo              # scan remote repo
deputy scan --ref v1.0.0                       # scan specific Git ref
deputy scan --format json                      # JSON output

# Remediation
deputy fix                                     # show remediation plan
deputy fix --apply .                           # apply fixes to directory

# Compare dependencies between Git refs
deputy diff main HEAD                          # diff main vs HEAD
deputy diff v1.0.0 v2.0.0                      # diff two tags

# Generate SBOM
deputy sbom --format cyclonedx-json --output sbom.json
deputy sbom --format spdx-json --output sbom.spdx.json

# List dependencies
deputy list                                    # list all dependencies
deputy list --only-direct                      # direct dependencies only

# Policy development
deputy policy eval policy.yaml                 # test policy
deputy policy lint policy.yaml                 # validate syntax
deputy policy lsp                              # language server

# Proxy (enforce policies at download time)
deputy proxy go -- go get github.com/pkg
deputy proxy npm -- npm install lodash
```

## Project Structure

```
main.go                      # entry point
internal/
  cli/cmd/                   # Cobra commands (scan.go, fix.go, diff.go, etc.)
                             # see internal/cli/cmd/root.go for command registration
  analysis/                  # OSV client (osv_client.go), vulnerability matching (vuln.go)
  inventory/                 # dependency detection
  policy/                    # CEL evaluation engine (eval.go)
  proxy/                     # package proxy server
  sbom/                      # SBOM generation
  remediation/               # fix planning
  gitutil/                   # Git operations (clone.go, diff.go, refs.go)
docs/                        # documentation
  commands/                  # command reference
  guides/                    # how-to guides (ci.md, workflows.md, agents.md)
policy/examples/             # 30+ CEL policy examples
```

Key entry points: [`main.go`](main.go) → [`internal/cli/cli.go`](internal/cli/cli.go) → [`internal/cli/cmd/root.go`](internal/cli/cmd/root.go)

## Tech Stack

- [Go] 1.21+ (uses [`toolchain`](https://go.dev/doc/toolchain) directive); use modern features like [generics](https://go.dev/blog/intro-generics), and packages like [`slices`](https://pkg.go.dev/slices), [`maps`](https://pkg.go.dev/maps), [`iter`](https://pkg.go.dev/iter), [`cmp`](https://pkg.go.dev/cmp), [`log/slog`](https://pkg.go.dev/log/slog), etc.
- [Cobra] for CLI; [Charm] for [Fang], [Lipgloss], etc. Prefer avoiding emojis in output, use ASCII or Unicode symbols, only if they add clarity; when in doubt, don't use them. Avoid them in most machine-readable output.
- [CEL] (Common Expression Language) for policies in a [YAML]-based [DSL].
- [OSV] API and [GCS] buckets for vulnerability data.
- [OSV-SCALIBR] for SCA inventory extraction (see [`internal/inventory/`](internal/inventory/)).
- [go-git] for Git operations (cloning, refs, diffs, commit snapshots). See [`internal/gitutil/`](internal/gitutil/).
- [PURL] (Package URL) for normalized package IDs.
- [Deps.dev] for dependency license, inventory, resolution, etc.
- [GitHub API] for various data when needed, but mostly avoided (accessing repos, licenses, etc).
- [Protobom] as a first-class feature, with [CycloneDX]/[SPDX] output for SBOMs.

[Go]: https://golang.org
[Cobra]: https://cobra.dev/
[Charm]: https://charm.sh/
[Fang]: https://github.com/charmbracelet/fang
[Lipgloss]: https://github.com/charmbracelet/lipgloss
[CEL]: https://cel.dev/
[YAML]: https://yaml.org/
[DSL]: https://en.wikipedia.org/wiki/Domain-specific_language
[OSV]: https://osv.dev
[OSV-SCALIBR]: https://github.com/google/osv-scalibr
[GCS]: https://cloud.google.com/storage
[go-git]: https://github.com/go-git/go-git
[Deps.dev]: https://deps.dev/
[PURL]: https://github.com/package-url/purl-spec
[Protobom]: https://github.com/protobom/protobom
[GitHub API]: https://docs.github.com/en/rest
[CycloneDX]: https://cyclonedx.org/
[SPDX]: https://spdx.dev/

## Policies (CEL)

Entrypoints define when a policy is evaluated. See [`internal/policy/entrypoints.go`](internal/policy/entrypoints.go) for canonical definitions.  
See [`internal/policy/evaluator.go`](internal/policy/evaluator.go) for CEL activation and variable bindings.

### Policy Examples

```yaml
# Block critical severity vulnerabilities
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.severity == "CRITICAL")
        reason: "Critical vulnerability found"
```

```yaml
# Require a license from an approved list
policies:
  - name: require-approved-license
    vars:
      allowed_licenses: ["MIT", "Apache-2.0", "BSD-3-Clause"]
    rules:
      - action: deny
        when: pkg.licenses.all(l, !(l in allowed_licenses))
        reason: "Package license is not in the approved list"
```

### Key Variables

The following variables are available in CEL expressions, depending on the policy entrypoint.

#### `pkg` object

Contains information about the dependency being analyzed. Available in [`scan_report`](internal/policy/entrypoints.go#L16) and [`scan_vulnerability`](internal/policy/entrypoints.go#L18) entrypoints.

| Field | Type | Description | Example Value |
|---|---|---|---|
| `name` | `string` | Name of the package | `"lodash"` |
| `version` | `string` | Version of the package | `"4.17.21"` |
| `ecosystem` | `string` | Package ecosystem | `"npm"` |
| `licenses` | `list(string)` | List of SPDX license identifiers | `["MIT"]` |

**Example Expressions for `pkg`:**

*   Deny a specific package:
    `pkg.name == 'left-pad'`
*   Deny packages with non-compliant licenses:
    `pkg.licenses.all(l, !(l in ['MIT', 'Apache-2.0']))`
*   Deny older versions of a package:
    `pkg.name == 'react' && pkg.version.startsWith('16.')`
*   Deny if license information is missing:
    `!has(pkg.licenses) || pkg.licenses.size() == 0`
*   Deny if license information is missing (using optionals):
    `pkg.?licenses.orValue([]).size() == 0`

---

#### `vulnerability` object

Represents a single vulnerability affecting a package. Available in the [`scan_vulnerability`](internal/policy/entrypoints.go#L18) entrypoint.

| Field | Type | Description | Example Value |
|---|---|---|---|
| `id` | `string` | Vulnerability ID (e.g., CVE, GHSA) | `"CVE-2021-44228"` |
| `severity` | `string` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `"CRITICAL"` |
| `isDirect` | `bool` | If the vulnerability is in a direct dependency | `true` |
| `fixedVersions` | `list(string)` | Versions containing a fix | `["2.15.0"]` |

**Example Expressions for `vulnerability`:**

*   Deny critical vulnerabilities:
    `vulnerability.severity == 'CRITICAL'`
*   Deny vulnerabilities in direct dependencies that have a fix:
    `vulnerability.isDirect && vulnerability.fixedVersions.size() > 0`
*   Deny a specific vulnerability by ID:
    `vulnerability.id == 'GHSA-jfh8-c2j2-2hch'`
*   Deny if a vulnerability has no fix and is `HIGH` or `CRITICAL`:
    `(!has(vulnerability.fixedVersions) || vulnerability.fixedVersions.size() == 0) && (has(vulnerability.severity) && vulnerability.severity in ['HIGH', 'CRITICAL'])`
*   Deny if a vulnerability has no fix and is `HIGH` or `CRITICAL` (using optionals):
    `size(vulnerability.?fixedVersions.orValue([])) == 0 && vulnerability.?severity.orValue('').upperAscii() in ['HIGH', 'CRITICAL']`

---

#### `vulnerabilities` list

A list of all `vulnerability` objects found in a scan report. Available in the [`scan_report`](internal/policy/entrypoints.go#L16) entrypoint. This is most commonly used with CEL macros like `exists`.

**Example Expressions for `vulnerabilities`:**

*   Deny if any critical vulnerabilities exist in the report:
    `vulnerabilities.exists(v, v.severity == 'CRITICAL')`
*   Deny if there are more than 5 vulnerabilities in total:
    `vulnerabilities.size() > 5`
*   Deny if all vulnerabilities are high severity (a strange but possible policy):
    `vulnerabilities.all(v, v.severity == 'HIGH')`

---

#### `request` object

Contains information about a package being requested through the proxy. Available in [`go_artifact_request`](internal/policy/entrypoints.go#L7), [`npm_artifact_request`](internal/policy/entrypoints.go#L9), and other proxy entrypoints.

| Field | Type | Description | Example Value |
|---|---|---|---|
| `package` | `string` | Name of the package being requested | `"react"` |
| `version` | `string` | Version of the package being requested | `"18.2.0"` |

**Example Expressions for `request`:**

*   Block downloads of a specific package:
    `request.package == 'express'`
*   Block downloads of unscoped public npm packages:
    `!request.package.startsWith('@')`

---

#### `env` object

Contains information about the environment in which `deputy` is running.

| Field | Type | Description | Example Value |
|---|---|---|---|
| `command` | `string` | The `deputy` command being executed | `"scan"` |

**Example Expressions for `env`:**

*   Apply a rule only during a `scan` command:
    `env.command == 'scan'`

Full spec: [`POLICY_SPEC.md`](POLICY_SPEC.md) • Examples: [`policy/examples/`](policy/examples/)

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | API access for SBOMs, licenses, and vulnerability data ([`internal/sbom/sbom.go`](internal/sbom/sbom.go), [`internal/analysis/licenses.go`](internal/analysis/licenses.go)) |
| `ANTHROPIC_API_KEY` | AI-assisted remediation ([`internal/cli/cmd/fix_agent_claude.go`](internal/cli/cmd/fix_agent_claude.go)) |
| `DEPUTY_LOG_LEVEL` | `debug`, `info`, `warn`, `error` ([`internal/cli/cli.go`](internal/cli/cli.go)) |
| `DEPUTY_CONFIG` | Path to config file (default: `.deputy.yaml`) ([`internal/config/config.go`](internal/config/config.go)) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (scan clean, command succeeded) |
| `1` | Error (vulnerabilities found, policy violation, runtime error) |

## Style

- Standard Go formatting (`go fmt`, `goimports`)
- Table-driven tests preferred
- Error handling: wrap with context using `fmt.Errorf("context: %w", err)`

## Development Patterns

### Adding a New Command

1. Create `internal/cli/cmd/yourcommand.go` (use `cobra.Command`)
2. Register in [`internal/cli/cmd/root.go`](internal/cli/cmd/root.go)
3. Add docs in [`docs/commands/`](docs/commands/)

### Common Tasks

| Task | Key Files |
|------|-----------|
| Vulnerability analysis | [`internal/analysis/osv_client.go`](internal/analysis/osv_client.go), [`severity.go`](internal/analysis/severity.go), [`group.go`](internal/analysis/group.go) |
| Ecosystem support | [`internal/inventory/`](internal/inventory/), [`internal/purlx/`](internal/purlx/), [`internal/proxy/`](internal/proxy/) |
| Policy features | [`internal/policy/eval.go`](internal/policy/eval.go), [`policy/examples/`](policy/examples/) |

## Debugging Tips

```bash
DEPUTY_LOG_LEVEL=debug deputy scan           # verbose logging
DEPUTY_LOG_FORMAT=json deputy scan           # structured logs
```

## Don't

- Don't skip tests before submitting changes (run [`blackbox_test.go`](blackbox_test.go) for CLI integration)