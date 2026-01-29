# Capabilities Reference

This page documents what Deputy can do across ecosystems, commands, and features.

## Ecosystem Support Matrix

| Ecosystem | Scan | SBOM | Proxy | Graph | License | Lockfiles |
|-----------|:----:|:----:|:-----:|:-----:|:-------:|-----------|
| **Go** | ✓ | ✓ | ✓ | ✓ | ✓ | go.mod, go.sum |
| **npm** | ✓ | ✓ | ✓ | ✓ | - | package-lock.json, yarn.lock, pnpm-lock.yaml |
| **PyPI** | ✓ | ✓ | ✓ | ✓ | - | requirements.txt, Pipfile.lock, poetry.lock |
| **RubyGems** | ✓ | ✓ | ✓ | ✓ | - | Gemfile.lock, *.gemspec |
| **Cargo** | ✓ | ✓ | - | ✓ | ✓ | Cargo.lock |
| **Maven** | ✓ | ✓ | - | - | - | pom.xml |
| **NuGet** | ✓ | ✓ | - | - | - | packages.lock.json, *.csproj |
| **Hex** | ✓ | ✓ | - | - | - | mix.lock |
| **Pub** | ✓ | ✓ | - | - | - | pubspec.lock |
| **CocoaPods** | ✓ | ✓ | - | - | - | Podfile.lock |
| **Packagist** | ✓ | ✓ | - | - | - | composer.lock |

**Additional extractors (via OSV-SCALIBR):**
- GitHub Actions (.github/workflows/*.yml)
- Terraform requirements (*.tf, *.tf.json)
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
