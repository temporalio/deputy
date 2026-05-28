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

## Resolution semantics

`deputy pin` is **faithful**: it pins each reference to the exact immutable
commit (or digest) that the reference resolves to *right now*. It never
substitutes a different release. If `uses: actions/foo@v7` currently resolves
to the `v7.6.0` commit, that is the commit you get — pinning never silently
upgrades or downgrades the code that runs.

This guarantee is why you sometimes see a less-specific version comment than you
might expect:

```yaml
# Floating major tag with a precise patch on the same commit:
uses: astral-sh/setup-uv@37802adc…  # v7.6.0   ← v7 and v7.6.0 are the same commit

# Floating major moved ahead of any patch tag (no vX.Y.Z on this commit):
uses: Swatinem/rust-cache@e18b497…  # v2       ← v2 is the most specific true tag

# Branch ref (e.g. a rolling channel):
uses: dtolnay/rust-toolchain@29eef33…  # stable ← pinned to the branch's commit
```

The comment always reflects the **most specific ref that genuinely points at the
pinned commit**. Deputy will not fabricate a precise version (e.g. `# v2.9.1`)
when that tag points at a *different* commit — doing so would misrepresent what
is actually pinned. The comment is also what Dependabot and Renovate read to
propose updates, so it is kept accurate to the pinned commit.

To intentionally move pins forward to the latest release in their channel, use
[`deputy pin update`](#subcommands) — that is the command that changes versions.
Plain `deputy pin` only makes an existing reference immutable; it does not change
which version you are on.

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
