# `deputy pin`

Pin dependencies to immutable references for supply chain security.

## Synopsis

```
deputy pin [directory] [flags]
deputy pin check [directory] [flags]
deputy pin verify [directory] [flags]
deputy pin update [directory] [flags]
```

## Supported Ecosystems

| Ecosystem | Mutable ref | Immutable pin | Resolution |
| --- | --- | --- | --- |
| `github-actions` | `uses: actions/checkout@v4` | `uses: actions/checkout@SHA # v4.2.2` | git ls-remote |
| `container-image` | `FROM alpine:3.19` | `FROM alpine:3.19@sha256:...` | OCI registry HEAD |

By default, both ecosystems are pinned. Use `--ecosystems` to narrow.

## Subcommands

| Subcommand | Network | Writes | Purpose |
| --- | --- | --- | --- |
| `pin` | yes | yes | Pin unpinned references |
| `pin check` | no | no | CI gate: are all refs pinned? |
| `pin verify` | yes | no | Provenance: are pins trustworthy? |
| `pin update` | yes | yes | Re-resolve pins to latest |

## Examples

```console
# Pin everything (actions + container images)
$ deputy pin

# Preview changes without modifying files
$ deputy pin --dry-run

# Pin only GitHub Actions
$ deputy pin --ecosystems github-actions

# Pin only container images
$ deputy pin --ecosystems container-image

# CI gate: fail if anything is unpinned
$ deputy pin check

# Verify GHA pins for fork/imposter commits
$ deputy pin verify

# Update pins to latest versions
$ deputy pin update --dry-run
```

## Flags

### Persistent (all subcommands)

| Flag | Default | Description |
| --- | --- | --- |
| `-e, --ecosystems` | `all` | Ecosystems to pin: `github-actions`, `container-image`, `all` |
| `-x, --exclude` | | Skip dependencies matching glob patterns |
| `-f, --format` | `text` | Output format: `text`, `json` |
| `-o, --output` | stdout | Output file |

### `pin` and `pin update`

| Flag | Default | Description |
| --- | --- | --- |
| `-n, --dry-run` | `false` | Show what would change without writing |
| `--skip-verification` | `false` | Skip fork/imposter verification |
| `--concurrency` | `4` | Max parallel network requests |

## Authentication

**GitHub Actions**: Set `GITHUB_TOKEN` or `GH_TOKEN` for fork/imposter verification (5000 req/hr). Basic pinning uses the git protocol and works without a token on public repos.

**Container images**: Uses the Docker credential keychain (`~/.docker/config.json`). Public images work without credentials.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Unpinned refs found (`check`), or pinning errors |
| `2` | Suspicious pins detected (possible supply chain attack) |

## Composability

```console
# Inventory -> scan -> pin -> verify (full supply chain workflow)
$ deputy list --ecosystems github-actions
$ deputy scan --ecosystems github-actions
$ deputy pin
$ deputy pin check
$ deputy pin verify
```

`deputy scan` also detects unpinned references as supply chain findings (`DEPUTY-SC-UNPINNED-ACTION`, `DEPUTY-SC-UNPINNED-IMAGE`), enabling policy-based enforcement without a separate `pin check` step.
