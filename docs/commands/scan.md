# `deputy scan`

Scan repositories, directories, or SBOM files for known vulnerabilities using OSV.

## When to use it

- Before releases to catch vulnerable dependencies early.
- In CI to gate merges or produce vulnerability artifacts.
- As a forensic tool (use `--as-of` / published-date filters).

## Common patterns

```console
# Scan current repo at HEAD
$ deputy scan

# Include uncommitted changes explicitly
$ deputy scan --ref WORKING

# Machine-readable output (CI artifacts)
$ deputy scan --format json --output scan.json

# Reduce noise by ignoring unfixed vulns 
$ deputy scan --ignore-unfixed

# Historical view: “What was known up to end of 2024?”
$ deputy scan --as-of 2024-12-31

# Scan an SBOM file (or stdin)
$ deputy scan sbom sbom.spdx.json
$ deputy sbom --format protobom-json | deputy scan sbom -
```

## Historical analysis

Deputy supports “time-window” and “as-of” views for vulnerability knowledge:

```console
# Vulns first published in 2025 or later
$ deputy scan --published-after=2025

# A specific month window
$ deputy scan --published-after=2025-02 --published-before=2025-03

# “State of known, fixable vulns at end of 2023”
$ deputy scan --as-of=2023 --ignore-unfixed
```

See [`docs/examples/historical-analysis.md`](../examples/historical-analysis.md) for more.

## Example output

For a realistic end-to-end workflow (including output), see:

- [`docs/examples/pipeline.md`](../examples/pipeline.md)

## Policies

Use `--policy` to evaluate CEL policies against the scan report and/or per-vulnerability entrypoints.
See [`docs/concepts/policies.md`](../concepts/policies.md).

## Code pointers

- CLI command: [`internal/cli/cmd/scan.go`](../../internal/cli/cmd/scan.go)
- Inventory + OSV queries: [`internal/inventory`](../../internal/inventory), [`internal/analysis`](../../internal/analysis)
