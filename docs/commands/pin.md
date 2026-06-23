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
| `mise` | `npm:prettier = "3"` (mise.toml) | `npm:prettier = "3.6.2"` | native metadata; optional host fallback allowlist |
| `asdf` | `nodejs 22` (.tool-versions) | `nodejs 22.14.0` | native metadata; optional host fallback allowlist |

By default, `deputy pin` and `deputy pin update` include all supported
ecosystems and do not execute host toolchain CLIs. For `mise` and `asdf`,
Deputy resolves versions natively where it has package or release metadata. To
allow host tools only as fallback for non-native backends, pass
`--allowed-host-bins` with absolute executable paths such as
`/opt/homebrew/bin/mise`. Deputy does not search `PATH`, and a host binary
cannot override a native-supported backend.

For `mise` and `asdf`, pinning rewrites fuzzy tool versions in `mise.toml` and
`.tool-versions` (channels like `latest`/`lts`, partial versions like `20`, and
Mise scopes like `prefix:` / `sub-`) to exact, reproducible versions. Native
resolution currently covers registry-backed backends such as `npm:`, `cargo:`,
`pipx:`, `pip:`, `gem:`, and `dotnet:`, core runtimes such as Go, Node.js,
Python, Terraform, Google Cloud SDK, Java's default OpenJDK shorthand
(`java = "21"`), Java Temurin selectors (`java = "temurin-21"`), and explicit
Java vendor selectors from Mise's Java metadata, well-known asdf runtime plugins
(`golang`, `nodejs`, `python`, `terraform`), `go:<import path>` tools
including Go proxy branch/revision selectors, repo-shaped `aqua:`, `ubi:`, and
`github:` tools, native CLI metadata sources such as 1Password CLI, and bare
Mise registry tools whose published `registry/<tool>.toml` entry points at a
native backend Deputy understands.
`pin check` makes no network calls, so it only uses local source data and
baked-in offline alias rules; `pin` and `pin update` can resolve additional
registry entries dynamically.
For `mise.toml`, plain `deputy pin` first preserves a compatible exact version
from the sibling `mise.lock`, when present. If the lockfile is absent, ambiguous,
or stale relative to the source selector, Deputy resolves from native upstream
metadata instead. `deputy pin update` is the explicit bump path for already
exact pins.
`deputy pin check` still covers mise/asdf without network access or a `mise`
binary and works as a CI gate. Array-valued tools are skipped (pin them
manually). See the [mise guide](../guides/mise.md).

## Resolution semantics

`deputy pin` is **faithful**: it pins each reference to the exact immutable
commit, digest, or tool version that the reference resolves to *right now*. For
formats with committed lockfiles, that means preserving a compatible locked
version before consulting upstream metadata. If `uses: actions/foo@v7` currently
resolves to the `v7.6.0` commit, that is the commit you get — pinning never
substitutes a different release.

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
Plain `deputy pin` makes an existing reference immutable; when a lockfile has
already recorded the exact version, that exact version is what gets written.

## Subcommands

| Subcommand | Network | Writes | Purpose |
| --- | --- | --- | --- |
| `pin` | yes | yes | Pin unpinned references; optional host fallback allowlist |
| `pin check` | no | no | CI gate: are all refs pinned? |
| `pin verify` | yes | no | Provenance: are pins trustworthy? |
| `pin update` | yes | yes | Re-resolve pins to latest; optional host fallback allowlist |

## Examples

```console
# Pin all supported ecosystems
$ deputy pin

# Preview changes without modifying files
$ deputy pin --dry-run

# Pin only GitHub Actions
$ deputy pin --ecosystems github-actions

# Pin only container images
$ deputy pin --ecosystems container-image

# Pin mise/asdf toolchains with an explicit host fallback allowlist
$ deputy pin --ecosystems mise,asdf --allowed-host-bins /opt/homebrew/bin/mise

# CI gate: fail if anything is unpinned
$ deputy pin check

# Verify GHA pins for fork/imposter commits
$ deputy pin verify

# Update pins to latest versions
$ deputy pin update --dry-run

# Update mise/asdf toolchain pins with an explicit host fallback allowlist
$ deputy pin update --ecosystems mise,asdf --allowed-host-bins /opt/homebrew/bin/mise
```

## Flags

### Persistent (all subcommands)

| Flag | Default | Description |
| --- | --- | --- |
| `-e, --ecosystems` | `all` | Ecosystems to pin: `github-actions`, `container-image`, `mise`, `asdf`, `all` |
| `-x, --exclude` | | Skip dependencies matching glob patterns (see [Exclude patterns](#exclude-patterns)) |
| `-f, --format` | `text` | Output format: `text`, `json` |
| `-o, --output` | stdout | Output file |

### `pin` and `pin update`

| Flag | Default | Description |
| --- | --- | --- |
| `-n, --dry-run` | `false` | Show what would change without writing |
| `--allowed-host-bins` | | Absolute paths to host binaries Deputy may execute for fallback resolution (repeatable or comma-separated) |
| `--verification` | `warn` | Provenance verification mode: `error`, `warn`, or `off` (see [Verification modes](#verification-modes)) |
| `--skip-verification` | `false` | Alias for `--verification=off` |
| `--concurrency` | `4` | Max parallel network requests |

## Verification modes

When pinning GitHub Actions, each resolved commit SHA is checked against the GitHub API for fork/imposter provenance (signed? reachable from the default branch?). `--verification` controls how findings affect the run:

| Mode | Flagged ref (likely imposter) | Exit code | Use case |
| --- | --- | --- | --- |
| `warn` (default) | Pinned anyway; reported as a warning | 0 | Automated pinning — a floating tag already resolves to that SHA at runtime, so freezing it is no riskier than leaving it floating |
| `error` | Left unpinned and reported | non-zero | Strict CI gate that must fail on any suspicious ref |
| `off` | Not checked | 0 | Offline or token-less runs (alias `--skip-verification`) |

Notes:

- A ref is flagged when its commit is unsigned **and** not reachable from the repository's default branch — common and legitimate for old major tags (`@v1`) and dist-bundled actions that tag releases off the default branch. `warn` pins these and surfaces the warning so a single such ref never aborts the whole repository's pinning.
- **Unverifiable** refs (rate limited, network error, missing `GITHUB_TOKEN`, renamed repo) are reported as warnings and pinned — they are *never* treated as imposters, in any mode.

## Exclude patterns

`--exclude` (repeatable) skips dependencies whose identity matches a glob. Patterns are matched with `/` as the path separator:

- `*` matches within a single path segment; `**` matches across segments (recursive).
- Each pattern is matched against both the dependency's repo identity (`owner/repo`) and its full path including any subpath (`owner/repo/subpath`).

Because the repo identity is matched too, an org- or repo-level pattern skips monorepo subpath actions, not just top-level ones:

| Pattern | Skips `temporalio/simple-action` | Skips `temporalio/private-actions/golang/setup` |
| --- | --- | --- |
| `temporalio/*` | yes | yes (matches the `temporalio/private-actions` repo) |
| `temporalio/**` | yes | yes (recursive) |
| `temporalio/private-actions` | no | yes (matches the repo, all subpaths) |
| `temporalio/private-actions/**` | no | yes |
| `actions/checkout` | — | exact full-path match |

Use `org/*` or `org/**` to skip a whole organization, e.g. to pin third-party actions while leaving your own org's actions untouched.

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
