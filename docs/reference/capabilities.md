# Capabilities Reference

This page documents what Deputy can do across ecosystems, commands, and features.

## Ecosystem Support Matrix

| Ecosystem | Scan | SBOM | Proxy | Graph | License | Manifest files | Lock/resolution files |
|-----------|:----:|:----:|:-----:|:-----:|:-------:|----------------|-----------------------|
| **Go** | ✓ | ✓ | ✓ | ✓ | ✓ | go.mod | - |
| **npm** | ✓ | ✓ | ✓ | ✓ | - | package.json | package-lock.json, yarn.lock, pnpm-lock.yaml |
| **PyPI** | ✓ | ✓ | ✓ | ✓ | - | pyproject.toml, setup.py, setup.cfg | requirements.txt, Pipfile.lock, poetry.lock, uv.lock |
| **RubyGems** | ✓ | ✓ | ✓ | ✓ | - | Gemfile, *.gemspec | Gemfile.lock |
| **Cargo** | ✓ | ✓ | - | ✓ | ✓ | Cargo.toml | Cargo.lock |
| **Maven** | ✓ | ✓ | - | - | - | pom.xml, build.gradle, build.gradle.kts | gradle/verification-metadata.xml |
| **NuGet** | ✓ | ✓ | - | - | - | *.csproj, *.fsproj | packages.lock.json |
| **Hex** | ✓ | ✓ | - | - | - | mix.exs | mix.lock |
| **Pub** | ✓ | ✓ | - | - | - | pubspec.yaml | pubspec.lock |
| **CocoaPods** | ✓ | ✓ | - | - | - | Podfile, *.podspec | Podfile.lock |
| **Packagist** | ✓ | ✓ | - | - | - | composer.json | composer.lock |
| **mise** | ✓¹ | ✓ | - | - | - | mise.toml, .mise.toml, .config/mise/config.toml | mise.lock |
| **asdf** | ✓¹ | ✓ | - | - | - | .tool-versions | - |

`go.sum` is a checksum database/cache for module integrity, not a dependency
lockfile, so it is intentionally not listed as a Go lock/resolution file.

¹ mise/asdf tools are inventoried under `pkg:mise` / `pkg:asdf` (matching
OSV-SCALIBR), which OSV does not index directly. For vulnerability scanning,
Deputy resolves tools installed from a registry-mapped backend (`npm:`, `cargo:`,
`pipx:`, `gem:`, `dotnet:`) to their canonical ecosystem, and the Go runtime to
the Go vulnerability database (stdlib/toolchain). Language runtimes without an
OSV ecosystem (e.g. node, python) are inventoried but not vuln-scanned. See the
[mise guide](../guides/mise.md) and [pin](../commands/pin.md).

**Additional extractors (via OSV-SCALIBR):**
- GitHub Actions (.github/workflows/*.yml)
- Haskell (cabal.project.freeze, stack.yaml.lock)
- R (renv.lock)
- C++ (conan.lock)
- OS packages (dpkg, apk, rpm) for container images

## Command Feature Matrix

| Feature | scan | fix | diff | graph | sbom | list | triage | proxy |
|---------|:----:|:---:|:----:|:-----:|:----:|:----:|:------:|:-----:|
| **Vulnerability lookup** | ✓ | ✓ | ✓ | ✓ | - | - | ✓ | ✓ |
| **Policy evaluation** | ✓ | ✓ | ✓ | - | ✓ | - | - | ✓ |
| **License enrichment** | ✓ | - | ✓ | - | ✓ | - | - | ✓ |
| **EPSS/KEV enrichment** | ✓ | - | - | - | - | - | - | - |
| **Graph resolution** | ✓ | - | - | ✓ | - | ✓ | - | - |
| **JSON output** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| **SARIF output** | ✓ | - | - | - | - | - | - | - |
| **Remote repos** | ✓ | - | ✓ | ✓ | ✓ | ✓ | - | - |
| **Container images** | ✓ | - | ✓ | - | ✓ | - | - | ✓ |
| **Git ref targeting** | ✓ | - | ✓ | ✓ | ✓ | ✓ | - | - |
| **Time-travel (--as-of)** | ✓ | - | ✓ | - | - | - | - | - |
| **AI agent support** | - | ✓ | - | - | - | - | ✓ | - |

## Output Format Matrix

| Command | text | json | sarif | dot | mermaid | d3 | cyclonedx | spdx | protobom |
|---------|:----:|:----:|:-----:|:---:|:-------:|:--:|:---------:|:----:|:--------:|
| **scan** | ✓ | ✓ | ✓ | - | - | - | - | - | - |
| **fix** | ✓ | ✓ | - | - | - | - | - | - | - |
| **diff** | ✓ | ✓ | - | - | - | - | - | - | - |
| **graph** | ✓ | ✓ | - | ✓ | ✓ | ✓ | - | - | - |
| **sbom** | - | - | - | - | - | - | ✓ | ✓ | ✓ |
| **list** | ✓ | ✓ | - | - | - | - | - | - | - |
| **triage** | ✓ | ✓ | - | - | - | - | - | - | - |

## Target Type Matrix

| Target Type | scan | diff | graph | sbom | list |
|-------------|:----:|:----:|:-----:|:----:|:----:|
| **Current directory** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Local path** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Remote repo URL** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Git ref (branch/tag/commit)** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Working tree (uncommitted)** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **SBOM file** | ✓ | ✓ | - | - | - |
| **Container image (remote)** | ✓ | ✓ | - | ✓ | - |
| **Container image (local daemon)** | ✓ | ✓ | - | ✓ | - |
| **PURL** | ✓ | - | - | - | - |

## Policy Entrypoint Matrix

Policies can be evaluated at different points depending on the command:

| Entrypoint | scan | diff | sbom | proxy | Description |
|------------|:----:|:----:|:----:|:-----:|-------------|
| `scan_report` | ✓ | - | - | - | Full scan results |
| `scan_vulnerability` | ✓ | - | - | - | Per-vulnerability |
| `diff_report` | - | ✓ | - | - | Full diff results |
| `diff_dependency_change` | - | ✓ | - | - | Per-package change |
| `diff_vulnerability` | - | ✓ | - | - | Vuln in changed deps |
| `container_diff_report` | - | ✓ | - | - | Container image diff |
| `sbom_report` | - | - | ✓ | - | SBOM generation |
| `go_artifact_request` | - | - | - | ✓ | Go module download |
| `npm_artifact_request` | - | - | - | ✓ | npm package download |
| `pypi_artifact_request` | - | - | - | ✓ | PyPI package download |
| `rubygems_artifact_request` | - | - | - | ✓ | RubyGems download |
| `oci_artifact_request` | - | - | - | ✓ | Container image pull |
| `dockerfile_report` | ✓ | - | - | - | Dockerfile analysis |
| `dockerfile_stage` | ✓ | - | - | - | Per-stage analysis |

## Enrichment Options

| Enrichment | Flag | Source | Description |
|------------|------|--------|-------------|
| **Licenses** | `--enrich-licenses` | deps.dev, scan | SPDX license identifiers |
| **EPSS** | `--enrich` | FIRST | Exploitation probability scores |
| **KEV** | `--enrich` | CISA | Known Exploited Vulnerabilities |
| **Graph** | `--with-graph` | deps.dev | Dependency path resolution |

## Proxy Ecosystem Support

| Ecosystem | Upstream | Entrypoint | License Lookup |
|-----------|----------|------------|:--------------:|
| **Go** | proxy.golang.org | `go_artifact_request` | ✓ |
| **npm** | registry.npmjs.org | `npm_artifact_request` | - |
| **PyPI** | pypi.org | `pypi_artifact_request` | - |
| **RubyGems** | rubygems.org | `rubygems_artifact_request` | - |
| **OCI** | Configurable | `oci_artifact_request` | - |

## Container Image Scanning

| Transport | Scheme | Config Extraction | Full Analysis |
|-----------|--------|:-----------------:|:-------------:|
| Remote registry | `docker://`, `oci://` | ✓ | ✓ |
| Docker daemon | `docker-daemon://` | - | Partial |
| OCI archive | `oci-archive://` | - | Partial |
| Tarball | `tarball://` | - | Partial |

## Feature Availability by Mode

### CI/CD Mode
- JSON output for artifact storage
- SARIF for GitHub Security tab integration
- Exit codes for pipeline gating
- Policy evaluation for automated decisions

### Developer Mode
- Human-readable table output
- Interactive triage with AI agents
- Working tree scanning (`--ref WORKING`)
- Time-travel queries (`--as-of`)

### Enterprise Mode
- Proxy for download-time enforcement
- JWT authentication for proxy access
- Policy bundling and distribution
- SBOM generation for compliance

## See Also

- [Ecosystem documentation](../concepts/inventory-and-sboms.md)
- [Policy framework](policy-framework.md)
- [Command reference](../commands/README.md)
