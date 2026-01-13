# Frequently Asked Questions

## General

### What is Deputy?

Deputy is a dependency management and security tool that:
- Scans for vulnerabilities using the OSV database
- Generates SBOMs (CycloneDX, SPDX)
- Creates remediation plans
- Enforces policies via CEL expressions
- Runs as a package proxy for download-time enforcement

### What ecosystems does Deputy support?

Deputy supports 15 ecosystems for scanning via [OSV-SCALIBR](https://github.com/google/osv-scalibr) and custom extractors:

| Ecosystem | Lockfiles / Manifests |
|-----------|----------------------|
| **Go** | go.mod, go.sum, Go binaries |
| **npm** | package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock |
| **PyPI** | requirements.txt, Pipfile.lock, poetry.lock, uv.lock, pdm.lock, setup.py, Conda environments |
| **RubyGems** | Gemfile.lock, gems.locked, *.gemspec |
| **Maven** | pom.xml, gradle.lockfile, JAR/WAR/EAR archives |
| **Cargo** | Cargo.lock, Cargo.toml, Rust binaries |
| **NuGet** | packages.lock.json, packages.config, *.deps.json |
| **Hex** | mix.lock |
| **Pub** | pubspec.lock |
| **CocoaPods** | Podfile.lock, Package.resolved |
| **Packagist** | composer.lock |
| **GitHub Actions** | .github/workflows/*.yml |
| **Haskell** | cabal.project.freeze, stack.yaml.lock |
| **R** | renv.lock |
| **C++** | conan.lock |

**Proxy support** (download-time enforcement) is available for Go, npm, PyPI, and RubyGems

### How does Deputy get vulnerability data?

Deputy queries the [OSV (Open Source Vulnerabilities)](https://osv.dev) database, which aggregates data from multiple sources including GitHub Advisory Database, NVD, and ecosystem-specific databases.

### Is Deputy free?

Yes. Deputy is open source under the MIT license.

---

## Installation

### How do I install Deputy?

```bash
go install github.com/picatz/deputy@latest
```

Requires Go 1.21+. See the [getting started guide](getting-started.md).

### Do I need Go installed to use Deputy?

Yes, currently. Deputy is distributed as a Go module. Prebuilt binaries may be available in future releases.

---

## Scanning

### How do I scan my project?

```bash
cd your-project
deputy scan
```

### How do I scan a remote repository?

```bash
deputy scan github.com/owner/repo
deputy scan github.com/owner/repo --ref v1.0.0
```

### How do I ignore vulnerabilities without fixes?

```bash
deputy scan --ignore-unfixed
```

### How do I get JSON output?

```bash
deputy scan --format json
deputy scan --format json --output results.json
```

### Why does scan show vulnerabilities in the Go stdlib?

Deputy reports vulnerabilities in the Go toolchain itself (shown as `stdlib`). Upgrade your Go version to remediate.

---

## Fixing Vulnerabilities

### How do I fix vulnerabilities?

```bash
# See the plan
deputy fix

# Apply automatically
deputy fix --apply
```

### Can Deputy automatically update my dependencies?

Yes, with `--apply`. For Go projects, it runs `go get` commands. For npm, it modifies package.json.

### What if a vulnerability has no fix?

Deputy shows these with "(no fix)" in output. Use `--ignore-unfixed` to filter them out, or wait for upstream patches.

---

## SBOM Generation

### What SBOM formats are supported?

- CycloneDX JSON (`--format cyclonedx-json`) - default
- SPDX JSON (`--format spdx-json`)
- Protobom JSON (`--format protobom-json`)

### How do I generate an SBOM?

```bash
deputy sbom --output sbom.json
deputy sbom --format spdx-json --output sbom.spdx.json
```

### How do I include license information?

```bash
deputy sbom --licenses
```

---

## Policies

### What is CEL?

CEL (Common Expression Language) is Google's expression language. It's type-safe, fast, and designed for security-critical evaluation.

### How do I write a policy?

```yaml
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)
        reason: critical vulnerability found
```

See the [policy cookbook](guides/policy-cookbook.md).

### How do I test my policy?

```bash
# Lint for syntax errors
deputy policy lint my-policy.yaml

# Test interactively
deputy policy repl

# Run against real data
deputy scan --policy my-policy.yaml
```

### Where can I find example policies?

See the [policy examples](../policy/examples/) for 30+ ready-to-use policies.

---

## Proxy

### What does the proxy do?

The proxy intercepts package downloads and evaluates policies before allowing the download. It can block vulnerable or non-compliant packages.

### How do I use the proxy for Go?

```bash
deputy proxy go -- go get github.com/example/pkg
```

### How do I run a standalone proxy server?

```bash
deputy proxy template > proxy.yaml
# Edit proxy.yaml
deputy proxy serve --config proxy.yaml
```

---

## Git Integration

### What Git references can I use?

- Branch names: `main`, `develop`
- Tags: `v1.0.0`
- Commit SHAs: `abc123`
- Relative: `HEAD~1`, `HEAD^`
- Time-based: `HEAD@{yesterday}`, `main@{1.week.ago}`

### What is WORKING?

`WORKING` refers to uncommitted changes in your working tree:

```bash
deputy diff main WORKING
```

### How do I compare two branches?

```bash
deputy diff main feature-branch
```

---

## CI/CD

### How do I use Deputy in GitHub Actions?

```yaml
- name: Scan for vulnerabilities
  run: |
    go install github.com/picatz/deputy@latest
    deputy scan --format json --output scan.json
```

See the [CI guide](guides/ci.md).

### How do I fail the build on vulnerabilities?

Use a policy to enforce thresholds. Deputy exits with code 1 when a policy denies:

```bash
# Create a policy that blocks critical vulnerabilities
deputy scan --policy severity-guardrail.yaml
```

Or check output programmatically:

```bash
deputy scan --format json | jq -e '.summary.critical == 0'
```

### How do I generate artifacts?

```bash
deputy scan --format json --output scan.json
deputy sbom --output sbom.json
```

---

## Performance

### Is Deputy slow?

First runs may be slow due to OSV database queries. Subsequent runs use caching. Use `DEPUTY_LOG_LEVEL=debug` to see timing.

### How do I speed up scans?

- Ensure good network connectivity to osv.dev
- Results are cached; repeat scans are faster
- Use `--ecosystems` to limit to specific ecosystems

---

## Troubleshooting

### Deputy can't find my dependencies

Ensure manifest/lock files exist and are valid:
- Go: `go.mod` (run `go mod tidy`)
- npm: `package.json` + `package-lock.json`
- Python: `requirements.txt` or `pyproject.toml`

### Network errors querying OSV

Check connectivity to `api.osv.dev`. See the [troubleshooting guide](guides/troubleshooting.md).

### "Permission denied" errors

Ensure Deputy has read access to your repository and write access if using `--apply`.

---

## See Also

- [Getting Started](getting-started.md)
- [Troubleshooting](guides/troubleshooting.md)
- [Glossary](glossary.md)
