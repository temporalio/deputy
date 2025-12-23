# `deputy scan`

Scan repositories, directories, or SBOM files for known vulnerabilities using OSV.

## Synopsis

```
deputy scan [repo] [flags]
deputy scan dir <directory> [flags]
deputy scan sbom <sbom-file> [flags]
```

## When to Use

- Before releases to catch vulnerable dependencies early
- In CI to gate merges or produce vulnerability artifacts
- As a forensic tool with `--as-of` / published-date filters
- To scan existing SBOMs from other tools

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--ref` | `-r` | `HEAD` | Git reference to scan (branch, tag, commit, or `WORKING`) |
| `--format` | `-f` | `text` | Output format: `text`, `json` |
| `--output` | `-o` | stdout | Output file path |
| `--ignore-unfixed` | | `false` | Hide vulnerabilities without a known fix |
| `--published-before` | | | Only show vulns published before this date |
| `--published-after` | | | Only show vulns published on/after this date |
| `--as-of` | | | Historical view up to this date (implies `--published-before`) |
| `--policy` | | | CEL policy file(s) to evaluate (repeatable) |
| `--ecosystems` | `-e` | all | Limit to specific ecosystems (see [Supported Ecosystems](#supported-ecosystems)) |
| `--show-symbols` | | `false` | Show affected symbols in text output |
| `--show-db-info` | | `false` | Show database metadata (e.g., review_status) |

### Date Format

Date flags accept: `YYYY`, `YYYY-MM`, `YYYY-MM-DD`, or RFC3339.

## Examples

### Basic Scanning

```console
# Scan current repo at HEAD
$ deputy scan

# Scan at a specific ref
$ deputy scan --ref v1.2.3

# Include uncommitted changes
$ deputy scan --ref WORKING

# Scan a remote repository
$ deputy scan github.com/hashicorp/vault --ref v1.16.0
```

### Output Formats

```console
# Machine-readable JSON for CI
$ deputy scan --format json --output scan.json

# Pipe to jq for processing
$ deputy scan --format json | jq '.vulnerabilities[] | {id: .id, severity: .severity}'
```

### Filtering

```console
# Hide unfixable vulnerabilities
$ deputy scan --ignore-unfixed

# Only Go and npm ecosystems
$ deputy scan --ecosystems go,npm

# Scan Java and Rust projects
$ deputy scan --ecosystems maven,cargo
```

## Supported Ecosystems

Deputy supports 15 ecosystems for scanning:

| Ecosystem | Flag Value | Lockfiles / Manifests |
|-----------|------------|----------------------|
| Go | `go` | go.mod, go.sum, Go binaries |
| npm | `npm` | package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock |
| PyPI | `pypi` | requirements.txt, Pipfile.lock, poetry.lock, uv.lock, pdm.lock, setup.py, Conda environments |
| RubyGems | `rubygems` | Gemfile.lock, gems.locked, *.gemspec |
| Maven | `maven` | pom.xml, gradle.lockfile, JAR/WAR/EAR archives |
| Cargo | `cargo` | Cargo.lock, Cargo.toml, Rust binaries |
| NuGet | `nuget` | packages.lock.json, packages.config, *.deps.json |
| Hex | `hex` | mix.lock |
| Pub | `pub` | pubspec.lock |
| CocoaPods | `cocoapods` | Podfile.lock, Package.resolved |
| Packagist | `packagist` | composer.lock |
| GitHub Actions | `github-actions` | .github/workflows/*.yml |
| Haskell | `haskell` | cabal.project.freeze, stack.yaml.lock |
| R | `r` | renv.lock |
| C++ | `cpp` | conan.lock |

Detection is powered by [OSV-SCALIBR](https://github.com/google/osv-scalibr) with custom extensions for GitHub Actions.
Binary analysis extracts dependencies from compiled Go and Rust executables

### Historical Analysis

```console
# What was known at end of 2024?
$ deputy scan --as-of 2024-12-31

# Vulns published in a specific window
$ deputy scan --published-after 2025-01 --published-before 2025-03

# Combine with ignore-unfixed for actionable results
$ deputy scan --as-of 2024-12-31 --ignore-unfixed
```

### Scanning Directories and SBOMs

```console
# Scan a directory (no Git context)
$ deputy scan dir ./vendor

# Scan an SBOM file
$ deputy scan sbom sbom.spdx.json

# Scan SBOM from stdin
$ deputy sbom --format protobom-json | deputy scan sbom -
```

### With Policies

```console
# Enforce severity guardrails
$ deputy scan --policy policy/severity-guardrail.yaml

# Multiple policies
$ deputy scan --policy policy/severity.yaml --policy policy/licenses.yaml
```

## Output

### Text Format

```
Scanned /path/to/repo @ HEAD (abc123d)
  Origin: https://github.com/example/repo.git

∴ Vulnerabilities Found:

github.com/example/pkg v1.2.3 [direct]:
  • CVE-2024-1234 [HIGH] (↑ v1.2.4)
    Description of the vulnerability
    Aliases: GHSA-xxxx-xxxx-xxxx
    Published: 2024-01-15

Vulnerability Summary:
  ! 3 require immediate attention (critical/high severity)
  ↑ 5 can be fixed by upgrading
```

### JSON Format

```json
{
  "repo": "/path/to/repo",
  "ref": "HEAD",
  "commit": "abc123d...",
  "generated": "2025-01-15T10:30:00Z",
  "packagesScanned": 42,
  "stats": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0,
    "fixable": 4
  },
  "vulnerabilities": [...]
}
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success (no policy violations) |
| `1` | Policy violations or scan errors |

## See Also

- Historical analysis: [`docs/examples/historical-analysis.md`](../examples/historical-analysis.md)
- Policies: [`docs/concepts/policies.md`](../concepts/policies.md)
- Pipeline example: [`docs/examples/pipeline.md`](../examples/pipeline.md)

## Code Pointers

- CLI: [`internal/cli/cmd/scan.go`](../../internal/cli/cmd/scan.go)
- Inventory: [`internal/inventory`](../../internal/inventory)
- OSV queries: [`internal/analysis`](../../internal/analysis)
