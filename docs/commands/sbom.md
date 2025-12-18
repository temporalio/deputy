# `deputy sbom`

Generate an SBOM for a repository at any Git reference.

## When to use it

- Compliance and audit (“what did we ship?”).
- Security baselining (“scan the SBOM, not just the repo”).
- Downstream tooling (CycloneDX/SPDX consumers, SBOM diffing, attestations).

## Common patterns

```console
# CycloneDX JSON (default)
$ deputy sbom --output sbom.cdx.json

# SPDX 2.3 JSON
$ deputy sbom --format spdx-json --output sbom.spdx.json

# Protobom JSON (intermediate model)
$ deputy sbom --format protobom-json --output sbom.protobom.json

# Exact current commit
$ deputy sbom --ref="$(git rev-parse HEAD)" --output sbom.cdx.json

# Remote GitHub repository by shorthand or URL
$ deputy sbom github.com/hashicorp/vault --ref=v1.16.0 --format=spdx-json
$ deputy sbom https://github.com/hashicorp/vault --ref=main --format=cyclonedx-json

# License enrichment
$ deputy sbom --enrich-licenses --license-source depsdev --output sbom.cdx.json

# Pipeline into scan
$ deputy sbom --format protobom-json | deputy scan sbom -
```

## Notes

- SBOMs can be generated for any valid Git ref: branches, tags, SHAs, or expressions like `HEAD~3`.
- When `--ref` is omitted, Deputy uses the working tree when applicable; provide an explicit `--ref` (commit SHA, tag) to capture an immutable state.
- Tip: if copy/pasting commands, prefer `--flag=value` form to avoid odd whitespace characters breaking flag parsing.

## Code pointers

- CLI command: [`internal/cli/cmd/sbom.go`](../../internal/cli/cmd/sbom.go)
- SBOM pipeline: [`internal/sbom`](../../internal/sbom)
