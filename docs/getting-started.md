# Getting Started

This page is for getting Deputy installed and useful in ~5 minutes.

## Install

### Go install (recommended)

```console
$ go install github.com/picatz/deputy@latest
$ deputy --version
```

Notes:
- Deputy’s `go.mod` uses the Go `toolchain` directive; use Go 1.21+ so `go` can fetch the pinned toolchain automatically.
- If you prefer a deterministic install, pin a tag/commit: `go install github.com/picatz/deputy@vX.Y.Z`.

### Prebuilt binaries

If your organization prefers prebuilt artifacts, use GitHub Releases (when available) and verify `deputy --version`.

### Build from source

```console
$ git clone https://github.com/picatz/deputy.git
$ cd deputy
$ go build ./...
$ go run . --help
```

## Your first runs

### 1) Scan the current repo

```console
$ deputy scan
```

Useful options:
- `--ignore-unfixed` to hide findings without a known fixed version.
- `--format json` to integrate with CI and store artifacts.
- `--as-of 2024-12-31` to ask “what was known up to this date?”

### 2) Turn findings into a plan (and optionally apply it)

```console
$ deputy fix
$ deputy fix --format json > plan.json
$ deputy fix --plan plan.json --apply .
```

### 3) Generate an SBOM

```console
$ deputy sbom --format spdx-json --output sbom.spdx.json
```

## Targets: local repo, directory, or remote

Deputy commands generally accept a **repo target**:

- Local path: `deputy scan .`
- Remote GitHub: `deputy scan github.com/hashicorp/vault --ref v1.16.0`

See [targets and refs](concepts/targets-and-refs.md) for the full mental model.

## Common environment variables

- Logging: `DEPUTY_LOG_LEVEL`, `DEPUTY_LOG_FORMAT`
- Optional config file: see the [configuration reference](reference/configuration.md)
- Optional: `GITHUB_TOKEN` (rate limits + fetch improvements during enrichment)
- Optional agents: `CODEX_API_KEY`, `ANTHROPIC_API_KEY`

## Next

- [Concepts](concepts/README.md)
- [Command reference](commands/README.md)
- [CI guide](guides/ci.md)
- [Examples](examples/README.md)
