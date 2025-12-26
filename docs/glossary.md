# Glossary

Key terms and concepts used throughout Deputy documentation.

## A

### Agent
An AI assistant (Claude, Codex, etc.) that can help implement remediation plans or triage vulnerabilities. See the [agents guide](guides/agents.md).

### Allowlist
A policy pattern that permits only specified items (licenses, packages, scopes). Opposite of blocklist.

### As-Of Date
A point-in-time filter (`--as-of`) showing only vulnerabilities known up to a specific date. Useful for historical analysis.

## B

### Blocklist
A policy pattern that denies specific items (packages, CVEs, licenses). Opposite of allowlist.

### Bundle
A compiled collection of CEL policies packaged into a single JSON file for distribution. Created with `deputy policy bundle`.

## C

### CEL (Common Expression Language)
Google's expression language used by Deputy for writing security policies. Type-safe, sandboxed, and designed for security-critical evaluation.

### CycloneDX
An OWASP standard for Software Bill of Materials (SBOM). Deputy supports CycloneDX JSON output via `deputy sbom --format cyclonedx-json`.

### CVE (Common Vulnerabilities and Exposures)
A unique identifier for publicly disclosed security vulnerabilities (e.g., CVE-2024-1234).

## D

### Direct Dependency
A package explicitly declared in your project's manifest (go.mod, package.json). Contrast with *transitive dependency*.

### Diff
The `deputy diff` command comparing dependencies between two Git references, showing additions, removals, upgrades, and vulnerability changes.

## E

### Ecosystem
A package management system: Go, npm, PyPI, RubyGems, GitHub Actions. Each has its own registry and PURL type.

### Entrypoint
A CEL policy evaluation context. Deputy has multiple entrypoints: `scan_vulnerability`, `go_artifact_request`, etc.

## F

### Fix
The `deputy fix` command generating remediation plans (upgrade commands) for vulnerable dependencies.

### Fixed Version
A package version where a vulnerability has been patched. Shown as `↑ v1.2.3` in scan output.

## G

### GHSA (GitHub Security Advisory)
GitHub's vulnerability database and identifier format (e.g., GHSA-xxxx-xxxx-xxxx).

### Git Ref
A Git reference: branch name, tag, commit SHA, or time-based expression (`HEAD@{yesterday}`).

## I

### Indirect Dependency
See *Transitive Dependency*.

### Inventory
The complete list of packages (dependencies) in a project. Generated internally before scanning or SBOM creation.

## L

### License
Software license (MIT, Apache-2.0, GPL-3.0, etc.). Deputy can enrich SBOMs with license data and enforce license policies.

### LSP (Language Server Protocol)
Protocol for editor integration. Deputy provides LSP support for CEL policy files via `deputy policy lsp`.

## M

### Manifest
A file declaring project dependencies: `go.mod`, `package.json`, `requirements.txt`, `Gemfile`.

## O

### OSV (Open Source Vulnerabilities)
Google's open vulnerability database format and API. Deputy's primary data source for vulnerability information.

## P

### Policy
A CEL expression defining security rules. Policies can `deny`, `warn`, or `allow` based on package attributes and vulnerabilities.

### Proxy
The `deputy proxy` command running an intercepting proxy that enforces policies at package download time.

### PURL (Package URL)
A standardized format for identifying packages: `pkg:golang/github.com/example/pkg@v1.2.3`. See [PURL spec](https://github.com/package-url/purl-spec).

## R

### Ref
Short for Git reference. See *Git Ref*.

### Remediation
Actions to fix vulnerabilities: upgrading packages, applying patches, or removing dependencies.

### REPL
Read-Eval-Print Loop. Deputy provides a CEL REPL via `deputy policy repl` for interactive policy development.

## S

### SBOM (Software Bill of Materials)
A structured inventory of software components. Deputy generates SBOMs in CycloneDX and SPDX formats.

### Scan
The `deputy scan` command analyzing dependencies for known vulnerabilities.

### Severity
Vulnerability severity level: CRITICAL, HIGH, MEDIUM, LOW. Based on CVSS scores in OSV data.

### SPDX
A Linux Foundation standard for SBOMs. Deputy supports SPDX JSON output via `deputy sbom --format spdx-json`.

## T

### Target
What Deputy operates on: local directory, Git repository path, or remote repository URL.

### Transitive Dependency
A package required by your direct dependencies (dependency of a dependency). Also called "indirect."

### Triage
The `deputy triage` command helping prioritize vulnerabilities for remediation.

## V

### Vulnerability
A security weakness in software. Deputy reports vulnerabilities from the OSV database with CVE/GHSA identifiers.

## W

### WORKING
Special ref indicating uncommitted changes in the working tree. Used in `deputy diff main WORKING`.

---

## See Also

- [Concepts](concepts/README.md)
- [Command reference](commands/README.md)
