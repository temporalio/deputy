# mise / asdf Toolchains

[mise](https://mise.jdx.dev) (and the older [asdf](https://asdf-vm.com)) manage a
project's dev tools — language runtimes (node, go, python), CLIs, and binaries —
from many backends (aqua, ubi, cargo, npm, pipx, go, gem, conda,
GitHub/GitLab/Forgejo, S3/HTTP, asdf/vfox plugins). That
makes `mise.toml` / `.tool-versions` a supply-chain surface like any package
manager, and Deputy treats it as a first-class ecosystem across `list`, `sbom`,
`scan`, `pin`, and `fix`.

## Taxonomy

Deputy mirrors OSV-SCALIBR's split, keyed by the config format:

| Config | Ecosystem | PURL |
| --- | --- | --- |
| `mise.toml`, `.mise.toml`, env/local variants, nested `config.toml` files | `mise` | `pkg:mise/<tool>@<version>` |
| `.tool-versions` | `asdf` | `pkg:asdf/<tool>@<version>` |

The PURL identity is the **manager** (mise/asdf), not the backend — so a
mise-managed tool is never conflated with a first-party library dependency. The
backend (`npm:`, `cargo:`, …) is preserved in component metadata.
Deputy recognizes Mise's documented root, nested, env-specific, and local config
filenames (for example `mise.test.toml`,
`.config/mise/config.test.local.toml`, and `mise/config.local.toml`), while
pinning skips developer-local TOML overrides.

## Inventory (`list`, `sbom`)

```bash
deputy list                 # includes mise/asdf tools, marked direct
deputy list --ecosystems mise
deputy sbom                 # mise tools become SBOM components
```

When a `mise.lock` sits next to `mise.toml`, Deputy enriches each tool with the
exact **locked version** and **per-platform integrity checksums**. In an SBOM,
each platform's asset (its URL + checksum) is emitted as a `DOWNLOAD` external
reference; a single-platform lock also sets the component-level hash.

## Scanning (`scan`)

OSV has no `mise`/`asdf` ecosystem, so the manager-level PURL matches no
advisories on its own. Deputy bridges this **without changing identity**:

- **Backend tools** with a registry mapping (`npm:`, `cargo:`, `pipx:`, `pip:`,
  `gem:`, `dotnet:`) are scanned under their canonical ecosystem — e.g.
  `npm:lodash` is checked against npm advisories. The exact locked version is
  preferred.
- **The Go runtime** (`go` / `golang`) is scanned against the Go vulnerability
  database (`stdlib` + `toolchain`), catching Go runtime CVEs.
- **Other runtimes** (node, python, terraform, Java) have no OSV ecosystem and
  are inventoried but not vuln-scanned (CPE/NVD matching would be required).

Findings are attributed back to `mise.toml` / `.tool-versions`.

## Pinning (`pin`)

```bash
deputy pin --ecosystems mise                      # npm:prettier = "3" -> "3.6.2"
deputy pin --ecosystems mise --allowed-host-bins /opt/homebrew/bin/mise
deputy pin check --ecosystems mise                # CI gate: no mise binary required
```

Pinning rewrites fuzzy versions (channels like `latest`/`lts`, partial versions
like `20`, and scopes like `prefix:1.20` / `sub-0.1:latest`) to exact,
reproducible versions. For `mise.toml`, plain `deputy pin` first prefers a
compatible exact version from the sibling `mise.lock` so it preserves the tool
version already resolved by Mise. If the lock entry is absent, ambiguous, or
stale relative to the source selector, Deputy resolves from native upstream
metadata instead. `deputy pin update` is the explicit command for moving an
already exact pin forward within its channel.

`deputy pin check` classifies the source declaration, not the lockfile:
`terraform = "1.9"` is still unpinned even when `mise.lock` records
`terraform@1.9.6`, because the shared source can float until `pin` rewrites it.

Deputy resolves these natively:

- Registry-backed tools: `npm:`, `cargo:`, `pipx:`, `pip:`, `gem:`, `dotnet:`.
- Core runtimes: Go, Node.js, Python, Terraform, Google Cloud SDK (`gcloud`),
  Java's default OpenJDK shorthand (`java = "21"`), Java Temurin selectors
  (`java = "temurin"` / `java = "temurin-21"`), and explicit Java vendor
  selectors available from Mise's Java metadata mirror (for example
  `java = "corretto-21"`), using release metadata from `go.dev`, `nodejs.org`,
  `python.org`, `releases.hashicorp.com`, Google Cloud SDK metadata, Mise's
  Java metadata mirror, and the Adoptium API.
- Well-known asdf runtime plugins: `asdf:golang`, `asdf:nodejs`,
  `asdf:python`, and `asdf:terraform`, routed through the same native runtime
  resolvers.
- Go module tools: `go:<import path>`, by probing deps.dev for the canonical
  module root before selecting a version. Branch-like Go selectors such as
  `release-0.19` resolve through Deputy's native Go proxy client to the
  canonical pseudo-version when the Go proxy supports the query.
- GitHub-release-backed tools: repo-shaped `aqua:`, `ubi:`, and `github:`
  specs, using GitHub release/tag metadata from `internal/forge/github/releases`.
  Source-specific tag formats are modeled where needed, such as Maven's
  `maven-3.9.x` tags, Yarn's `@yarnpkg/cli/4.x` tags, and ClickHouse
  `v25.x-stable` tags.
- Bare registry tools whose Mise registry entry lists a native backend. Deputy
  reads Mise's published `registry/<tool>.toml` source from
  <https://github.com/jdx/mise/tree/main/registry> with bounded, retrying HTTP
  and follows the first backend it can model natively, including package-backed
  `npm:`/`pipx:` entries and GitHub-release-family entries. Common registry
  aliases such as `op` -> `1password`, `aws` -> `aws-cli`, and `azure-cli` ->
  `azure` are understood. Deputy does not invoke `mise registry`.
- Native CLI release sources that are not ordinary GitHub releases, including
  1Password CLI's app-update metadata and Google Cloud SDK's rapid-channel
  metadata.

To allow host tools only as fallback for non-native backends, pass
`--allowed-host-bins` with absolute executable paths such as
`/opt/homebrew/bin/mise`. Deputy never searches `PATH`, and an allowed host
binary cannot override a native-supported backend. Array-valued tools are
skipped — pin them manually. The exact version is written with no extra comments,
matching a clean committed `mise.toml`.

Native resolver work that remains:

- Alias-only registry names whose file lives under a different canonical tool
  name need either a baked-in alias or a future whole-registry index cache.
  `pin check` makes no network calls, so it cannot discover new aliases
  dynamically.
- Non-repo-shaped `aqua:`, `ubi:`, and `github:` specs need backend metadata
  before Deputy can resolve them natively.
- Arbitrary `asdf:` and `vfox:` plugin tools need plugin metadata modeling where
  possible; host mise fallback remains the parity option for plugin-scripted
  behavior.
- Project settings that override `java.shorthand_vendor` and non-default Java
  `release_type` options need dedicated modeling of Mise's Java settings before
  Deputy can resolve them natively.
- `http:` has no discoverable latest version unless the URL or surrounding
  metadata identifies a version source.

The implementation is aligned with Mise's documented configuration environments,
backend prefixes, version scopes, and Java tool behavior:
<https://mise.jdx.dev/configuration.html>,
<https://mise.jdx.dev/configuration/environments.html>,
<https://mise.jdx.dev/dev-tools/backends/>, and
<https://mise.jdx.dev/lang/java.html>. Java release selection uses Mise's Java
metadata mirror (<https://mise-java.jdx.dev/>) and, for Temurin, Adoptium's
release metadata endpoint: <https://api.adoptium.net/v3/info/release_versions>.

## Fixing (`fix`)

`deputy fix` proposes source-aware remediation:

- A vulnerable backend tool → `mise use --path mise.toml npm:lodash@<fixed>`.
- A Go stdlib/toolchain CVE is fixed at **each** declaring source: a `go.mod`
  `go` directive gets `go get go@<fixed>`, while a `mise.toml` `go` entry gets a
  distinct `mise use --path mise.toml go@<fixed>`. If both declare the Go
  version, both fixes are produced.
- Fix commands always target the detected config file via `--path` (by
  basename, since the command runs in the manifest's directory). Without it,
  `mise use` picks its own write target, so a finding from an
  environment-specific config like `mise.production.toml` would otherwise be
  "fixed" in `mise.toml` while the vulnerable higher-precedence pin stays in
  effect.

## Hardening

Pin exact versions (above), commit `mise.lock` (`lockfile = true`), set a
`minimum_release_age` cooldown, and keep verification on (cosign/SLSA/GitHub
attestations). See the `secure-mise-toolchain` skill for the guided model.
(Codifying these as enforceable CEL policy inputs is planned.)
