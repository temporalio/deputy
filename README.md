# deputy

```console
$ deputy HEAD~1500 HEAD
...
```

## SBOM Generation

Generate an SBOM for a specific ref/tag/commit using Protobom as the intermediary model. Outputs CycloneDX JSON, SPDX 2.3 JSON, or the raw Protobom JSON.

Examples:

```console
# Quick start (stdout)
$ deputy sbom --format spdx-json
$ deputy sbom -f spdx-json

# CycloneDX JSON
$ deputy sbom --ref=v1.28.0 --format=cyclonedx-json --output=sbom.cdx.json

# Limit to specific ecosystems (auto-detects by default)
$ deputy sbom --ref=main --ecosystems=go,npm

# SPDX 2.3 JSON
$ deputy sbom --ref=v1.28.0 --format=spdx-json --output=sbom.spdx.json

# Protobom JSON (intermediary format)
$ deputy sbom --ref=v1.28.0 --format=protobom-json --output=sbom.protobom.json

# Remote GitHub repository by shorthand or URL
$ deputy sbom github.com/hashicorp/vault --ref=v1.16.0 --format=spdx-json
$ deputy sbom https://github.com/hashicorp/vault --ref=main --format=cyclonedx-json

# Enrich licenses via deps.dev, local scan, or both
$ deputy sbom --ref=v1.28.0 --enrich-licenses --license-source=depsdev --format=spdx-json
$ deputy sbom --ref=v1.28.0 --enrich-licenses --license-source=scan    --format=spdx-json
$ deputy sbom --ref=v1.28.0 --enrich-licenses --license-source=both    --format=spdx-json
```

Notes:
- SBOMs can be generated for any valid Git ref: branches, tags, SHAs, or expressions like `HEAD~3`.
- Multi-ecosystem inventory is powered by `osv-scalibr` plugins; by default it scans all supported ecosystems.
- For GitHub, setting `GITHUB_TOKEN` can improve rate limits and enables authenticated fetching during license enrichment of dependencies.
- Document names prefer the Go module path (e.g., `github.com/hashicorp/vault@v1.16.0`) and Go PURLs are normalized (e.g., `pkg:golang/github.com/hashicorp/vault/sdk@...`).
- Tip: if copy/pasting commands, prefer `--flag=value` form to avoid odd whitespace characters breaking flag parsing.
- Optional: add a human-friendly context header with `--show-context` (printed to stderr; does not affect JSON):
  `deputy sbom --ref=v1.28.0 --format=spdx-json --show-context`

## Working Tree Compare

When run with no arguments, deputy compares the default branch with your current state:

```console
$ deputy
Comparing dependencies: main → HEAD
No dependency changes detected.

# If go.mod or go.sum have uncommitted changes, deputy compares against WORKING instead:
$ go get -u ./...
$ deputy
Comparing dependencies: main → WORKING
...
```

You can also be explicit: `deputy main WORKING`.

## Vulnerability Scan

Scan a repository for known vulnerabilities using osv.dev. Uses scalibr to inventory dependencies at a given ref and consolidates results for an actionable report.

Examples:

```console
# Scan the current repository (HEAD)
$ deputy scan

# Scan a specific ref
$ deputy scan --ref=main
$ deputy scan v1.2.3

# Scan a local path or remote GitHub repo
$ deputy scan ./path/to/repo --ref=v1.2.3
$ deputy scan github.com/hashicorp/vault --ref=v1.16.0

# JSON output (machine-readable)
$ deputy scan --format=json > report.vulns.json
```

Notes:
- Output formats: `text` (default) or `json`.
- Currently focuses OSV lookups for Go module ecosystem.
- Network is required for OSV queries; failures are reported as warnings and do not stop SBOM generation or scanning.
- Known module deprecations may be highlighted with suggested replacements (e.g., `github.com/aws/aws-sdk-go` → `github.com/aws/aws-sdk-go-v2`).

```console
$ deputy --list-refs
```

```console
$ deputy v1.27.0 v1.28.0
Comparing dependencies: v1.27.0 → v1.28.0
Scanning packages in base reference b1ae42e0 ...
Scanning packages in target reference b0365052 ...
...
```
