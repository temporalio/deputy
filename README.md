# deputy

```console
$ deputy HEAD~1500 HEAD
...
```

## At a Glance

| Command | Purpose |
| --- | --- |
| `deputy diff` | Compare dependency sets between refs (default when no subcommand is provided). |
| `deputy scan` | Inventory dependencies and query OSV for known vulnerabilities (repos, dirs, or SBOMs). |
| `deputy sbom` | Emit CycloneDX/SPDX/Protobom SBOMs for any Git ref (with optional license enrichment). |
| `deputy list` | Dump normalized PURLs (text/TSV/JSON) for quick auditing or scripting. |
| `deputy fix` | Turn scan results into upgrade commands/plan JSON, optionally apply them or delegate to an AI agent. |
| `deputy triage` | Summarize vulnerability hotspots and prioritize remediation (text or JSON, with optional AI analysis). |

All commands honor the global logging flags (`--log-level`, `--log-format`) so you can switch between human-readable output and structured logs for CI/CD.

## Agents & Automation

Deputy can hand remediation plans or triage summaries to external agents when you need help parsing large reports or editing code automatically.

- `deputy fix --agent codex …` launches the Codex CLI in your repository and lets it run commands/edit files according to the remediation plan. Require `CODEX_API_KEY` and (optionally) `--agent-model`, `--agent-sandbox`, `--agent-thread`, etc.
- `deputy fix --agent claude …` or `deputy triage --agent claude …` streams the JSON summary to Anthropic's Messages API (`ANTHROPIC_API_KEY`), returning prioritized guidance without granting shell access.
- Both subcommands accept `--plan plan.json` (saved via `deputy fix --format json`) so you can review a plan once and reapply or re-analyze it later.
- Use `--agent-sandbox read-only` when you only want the agent to reason about code, and `--agent-sandbox workspace-write` or `danger-full-access` when Codex needs to touch files.

If you prefer a manual workflow, you can skip `--agent` entirely and run the recommended upgrade commands yourself.

## Dependency Diff

Explicitly compare dependency changes between Git references. This mirrors the default behavior when running `deputy` without a subcommand, but provides a dedicated, intuitive entrypoint alongside `scan` and `sbom`.

Examples:

```console
# Default: Compare default branch → HEAD (or → WORKING if go.mod/go.sum have uncommitted changes)
$ deputy diff

# Compare default branch → a ref
$ deputy diff feature-branch

# Compare two explicit refs
$ deputy diff v1.27.0 v1.28.0
$ deputy diff origin/main feature/user-auth

# Time-based refs
$ deputy diff "HEAD@{yesterday}" HEAD
$ deputy diff "main@{1.week.ago}" main

# Specify a repository path
$ deputy diff --repo=./path/to/repo v1.2.0 v1.3.0

# Speed up by skipping vulnerability scanning
$ deputy diff --skip-vuln-scan
```

Notes:
- Supports branches, tags, SHAs, remote refs, and time-based refs (e.g., `HEAD@{1.week.ago}`).
- Uses non-destructive snapshots; your working tree isn’t modified.

### Vulnerabilities in Diff

The diff view performs an OSV scan of the target dependency set and renders a cohesive report:

- Single header for vulnerabilities, with changed dependencies first
- Unchanged dependencies are hidden by default unless they contain CRITICAL vulnerabilities
- A dim divider separates unchanged dependencies with a short reason when auto-shown
- A combined summary and recommended actions section covers everything that’s displayed

Flags:

```console
# Always show unchanged vulnerabilities
$ deputy diff v1.27.0 v1.28.0 --show-unchanged

# Hide unfixed vulnerabilities (mirrors scan)
$ deputy diff v1.27.0 v1.28.0 --ignore-unfixed

# Control threshold for auto-showing unchanged vulns
# Options: none | low | med | high | critical | any (default: critical)
$ deputy diff v1.27.0 v1.28.0 --unchanged-threshold high
```

Examples (condensed):

```text
∴ Vulnerabilities

stdlib v1.24.1 [direct]:
  • CVE-2025-22871 [CRITICAL] (↑ v1.24.2)
  • CVE-2025-22874 [HIGH] (↑ v1.24.4)

─── Unchanged dependencies (Critical severity present) ───

github.com/golang-jwt/jwt/v4 v4.5.1 [direct]:
  • CVE-2025-30204 [HIGH] (↑ v4.5.2) [2 related]

Vulnerability Summary:
  ! 4 require immediate attention (critical/high severity)
  ↑ 6 can be fixed by upgrading

Recommended Actions:
  1. Upgrade Go toolchain to v1.24.6 (update 'go' directive in go.mod)
  2. Upgrade critical/high modules first
       • go get github.com/golang-jwt/jwt/v4@v4.5.2
       • go mod tidy
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
- When `--ref` is omitted or set to `HEAD`, the SBOM uses the local working tree if available (includes uncommitted changes). Use `--ref=HEAD` to capture the exact last commit.
- Multi-ecosystem inventory is powered by `osv-scalibr` plugins; by default it scans all supported ecosystems.
- For GitHub, setting `GITHUB_TOKEN` can improve rate limits and enables authenticated fetching during license enrichment of dependencies.
- Document names prefer the Go module path (e.g., `github.com/hashicorp/vault@v1.16.0`) and Go PURLs are normalized (e.g., `pkg:golang/github.com/hashicorp/vault/sdk@...`).
- Tip: if copy/pasting commands, prefer `--flag=value` form to avoid odd whitespace characters breaking flag parsing.
- Optional: add a human-friendly context header with `--show-context` (printed to stderr; does not affect JSON):
  `deputy sbom --ref=v1.28.0 --format=spdx-json --show-context`

## Dependency List

List the dependency inventory as normalized PURLs (Package URLs) suitable for grepping and jq.
This mirrors what the SBOM command discovers: one entry per discovered package (no dedup), with
direct/indirect classification derived from go.mod.

Examples:

```console
# Current repository at HEAD (uses working tree when applicable)
$ deputy list

# Specific ref/commit/tag
$ deputy list --ref main
$ deputy list --ref v1.2.3

# TSV for pipelines: purl<TAB>direct
$ deputy list --format tsv | cut -f1

# JSON for jq
$ deputy list --format json | jq '.items[] | {purl: .purl, direct: .isDirect}'

# Only direct dependencies (from go.mod without // indirect)
$ deputy list --only-direct

# Remote repository
$ deputy list github.com/gin-gonic/gin --ref v1.9.0
```

Output formats:

- text: aligned, colored columns `PURL` and `DIRECT` (indirect is dimmed)
- tsv: `purl\tdirect` (use `--no-header` to omit header)
- json: structured, includes fields for `ecosystem`, `name`, `version`, `module`, `isDirect`, `purl`

Notes:

- No dedup: every discovered package is emitted, similar to SBOM output.
- Sorting: results are sorted by PURL for stable output.
- Directness: computed using exact module paths in go.mod with a longest-prefix check against the package import path.
- When `--ref` is omitted or set to `HEAD`, the inventory uses the working tree if available. Use `--ref=HEAD` to capture the last commit exactly.

Example (text, condensed):

```text
PURL                                                  DIRECT
pkg:golang/github.com/gorilla/mux@1.8.1              direct
pkg:golang/github.com/google/uuid@1.6.0              direct
pkg:golang/golang.org/x/net@0.39.0                   indirect
pkg:golang/cloud.google.com/go/storage@1.51.0        direct
```

## Remediation Plans

Turn vulnerability scan results into actionable upgrade commands with `deputy fix`.
When run without `--report`, the command performs the same multi-ecosystem scan as
`deputy scan`, summarizes required upgrades, and groups the recommended commands by
manifest. You can also feed it the JSON output from `deputy scan --format json` if
you already have scan results from CI.

Examples:

```console
# Scan the current repository and show remediation steps
$ deputy fix

# Target a remote repository directly
$ deputy fix github.com/hashicorp/vagrant --ignore-unfixed

# Reuse an existing JSON report
$ deputy scan --format json --output scan.json
$ deputy fix --report scan.json

# Pipe a report directly
$ deputy scan --format json --output - | deputy fix --report -

# Reuse a saved remediation plan
$ deputy fix --plan plan.json

# Emit a machine-readable remediation plan
$ deputy fix --format json > plan.json

# Apply runnable commands (e.g., go get / npm install) in place
$ deputy fix --apply

# Apply commands from a saved plan in the current repository
$ deputy fix --plan plan.json --apply .

# Let Codex implement manual steps automatically
$ CODEX_API_KEY=sk-... deputy fix --plan plan.json --agent codex --agent-model gpt-4.1
```

Notes:
- `--ref`, `--ecosystems`, and the published-date filters mirror the `scan` flags.
- `--apply` executes only the commands flagged as runnable (e.g., `go get`, `npm install`) and
  runs them from the manifest directory. Manual steps (Gemfile edits, etc.) are still shown but
  not executed.
- `--plan PATH` replays a previously generated remediation plan (via `--format json`); pair it
  with a repository path argument when using `--apply` so commands run in the correct directory.
- `--report` continues to accept JSON output from `deputy scan --format json`; use `--plan` for
  remediation plans.
- `--format json` emits the full remediation plan (target metadata, stdlib upgrades, and
  remediation commands) for CI/CD automation.
- `--agent codex` streams the plan to the Codex CLI so it can edit files, run commands, and finish
  the remediation autonomously; set `CODEX_API_KEY` (and optionally `--agent-model`, `--agent-sandbox`,
  or `--agent-thread`) before enabling this mode.
- `--agent claude` sends the plan to the Anthropic Messages API (set `ANTHROPIC_API_KEY`) and streams
  the textual guidance back to the terminal—useful when you want prioritized advice without granting
  an agent direct access to your repo.

### Global logging flags

All commands accept two global logging flags (or the equivalent environment variables):

| Flag | Env Var | Description |
| ---- | ------- | ----------- |
| `--log-level {debug,info,warn,error}` | `DEPUTY_LOG_LEVEL` | Controls verbosity (default: `info`). |
| `--log-format {text,json}` | `DEPUTY_LOG_FORMAT` | Selects human-readable vs structured logs (default: `text`). |

Example:

```console
$ DEPUTY_LOG_LEVEL=debug DEPUTY_LOG_FORMAT=json deputy scan --ref main --ignore-unfixed
```

## Vulnerability Triage

`deputy triage` analyzes a repository (or a saved `deputy scan --format json` report) and produces a
prioritized view of the vulnerabilities affecting it. Use this command when you want to understand
which findings are most urgent before diving into remediation.

Examples:

```console
# Quick triage of the current repo
$ deputy triage

# Triage a remote repository and ignore unfixed issues
$ deputy triage github.com/hashicorp/vagrant --ignore-unfixed

# Triage an existing scan report
$ deputy triage --report scan.json --format json

# Ask Codex to prioritize the results and suggest next steps
$ CODEX_API_KEY=sk-... deputy triage --agent codex --agent-model gpt-4.1
```

Notes:
- Triaging without `--report` performs the same multi-ecosystem scan as `deputy scan`.
- `--format json` emits the structured summary (target metadata, severity stats, and the top
  impacted packages) so CI systems can archive or diff the triage output.
- `--agent codex` sends the summary JSON to Codex so it can highlight the risks that matter most and
  propose remediation/testing plans. Provide a repository path argument (or run inside the repo) so
  the agent can inspect the code if needed. `--agent claude` is also supported for text-only
  prioritization when you prefer to keep the repo read-only.

Typical output (condensed):

```text
Remediation Plan:
  Target: github.com/hashicorp/vagrant@main
  Commit: 1a2b3c4
  • Upgrade Go toolchain to v1.22.2 (update 'go' directive in go.mod)
  • Apply dependency upgrades (4 total, 3 runnable)
       go.mod:
         ↑ go get github.com/hashicorp/vagrant-plugin-sdk@v1.0.5
         ↻ go mod tidy  # locks
       vagrant.gemspec:
         › Edit vagrant.gemspec to require rexml >= v3.3.9  # manual edit
```

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
Shorthand: you can use a single dot for the working tree: `deputy main .`.

## Time-based References

You can compare against a point in time using Git’s `@{...}` syntax with friendly units.

Examples:

```console
# Yesterday vs HEAD
$ deputy "HEAD@{yesterday}" HEAD

# A week ago on a branch
$ deputy "main@{1.week.ago}" main

# A few months ago
$ deputy "main@{3.month.ago}" main

# A year ago
$ deputy "HEAD@{1.year.ago}" HEAD
```

Supported shorthands inside `@{...}`:
- now, yesterday
- N.second(s).ago: s, sec, second, seconds
- N.minute(s).ago: m, min, minute, minutes
- N.hour(s).ago: h, hr, hour, hours
- N.day(s).ago: d, day, days
- N.week(s).ago: w, wk, week, weeks
- N.month(s).ago: mo, mon, month, months (calendar-aware)
- N.year(s).ago: y, yr, year, years (calendar-aware)

Notes:
- Always quote refs containing `@{...}` to avoid shell expansion.
- Months and years use calendar-aware subtraction (not fixed durations).

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

# Reduce noise by ignoring unfixed vulnerabilities (like Trivy)
$ deputy scan --ignore-unfixed

# Historical / Time-filtered views
$ deputy scan --as-of=2024-12-31           # What was known up to end of 2024
$ deputy scan --published-after=2025        # Vulns first published in 2025 or later
$ deputy scan --published-after=2025-02 --published-before=2025-03   # February 2025 window
$ deputy scan --as-of=2023 --ignore-unfixed # State of known, fixable vulns at end of 2023
$ deputy diff v1.0.0 v2.0.0 --as-of=2022-12-31 # Changes considering knowledge available by 2022 year end
```

Notes:
- Output formats: `text` (default) or `json`.
- Currently focuses OSV lookups for Go module ecosystem.
- Scanning without `--ref` uses the working tree when on HEAD (includes uncommitted changes). Use `--ref=HEAD` to scan the exact last commit.
- `--ignore-unfixed` filters out vulnerabilities without a known fixed version. Module deprecations are still shown (e.g., migrate `github.com/aws/aws-sdk-go` → `github.com/aws/aws-sdk-go-v2`).
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

```console
$ deputy "HEAD@{1.year.ago}" HEAD
Comparing dependencies: HEAD@{1.year.ago} → HEAD
Scanning packages in base reference 3c49088d ...
Scanning packages in target reference d2197f7f ...

Dependency Changes:
  + cel.dev/expr @ 0.20.0 [Apache-2.0]
  ↑ cloud.google.com/go @ 0.114.0 → 0.118.3 [Apache-2.0, BSD-3-Clause]
  ↑ cloud.google.com/go/auth @ 0.5.0 → 0.15.0 [Apache-2.0]
  ↑ cloud.google.com/go/auth/oauth2adapt @ 0.2.2 → 0.2.7 [Apache-2.0]
  ↑ cloud.google.com/go/compute/metadata @ 0.3.0 → 0.6.0 [Apache-2.0]
  ↑ cloud.google.com/go/iam @ 1.1.8 → 1.4.2 [Apache-2.0]
  + cloud.google.com/go/monitoring @ 1.24.1 [Apache-2.0]
  ↑ cloud.google.com/go/storage @ 1.41.0 → 1.51.0 [Apache-2.0]
  + dario.cat/mergo @ 1.0.1 [BSD-3-Clause]
  + filippo.io/edwards25519 @ 1.1.0 [BSD-3-Clause]
  + github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp @ 1.27.0 [Apache-2.0]
  + github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric @ 0.51.0 [Apache-2.0]
  + github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping @ 0.51.0 [Apache-2.0]
  + github.com/Masterminds/goutils @ 1.1.1 [Apache-2.0]
  + github.com/Masterminds/semver/v3 @ 3.3.0 [MIT]
  + github.com/Masterminds/sprig/v3 @ 3.3.0 [MIT]
  ↑ github.com/apache/thrift @ 0.16.0 → 0.21.0 [Apache-2.0, BSD-3-Clause]
  ↑ github.com/aws/aws-sdk-go @ 1.53.15 → 1.55.6 [Apache-2.0, BSD-3-Clause]
  ↑ github.com/benbjohnson/clock @ 1.1.0 → 1.3.5 [MIT]
  + github.com/cncf/xds/go @ 0.0.0-20250121191232-2f005788dc42 [Apache-2.0]
  ↑ github.com/cpuguy83/go-md2man/v2 @ 2.0.4 → 2.0.6 [MIT]
  ↑ github.com/dgryski/go-farm @ 0.0.0-20200201041132-a6ae2369ad13 → 0.0.0-20240924180020-3414d57e47da [MIT]
  + github.com/envoyproxy/go-control-plane/envoy @ 1.32.4 [Apache-2.0]
  + github.com/envoyproxy/protoc-gen-validate @ 1.2.1 [Apache-2.0]
  ↑ github.com/fatih/color @ 1.17.0 → 1.18.0 [MIT]
  ↑ github.com/go-faker/faker/v4 @ 4.4.1 → 4.6.0 [MIT]
  ↑ gopkg.in/go-jose/go-jose.v2 → github.com/go-jose/go-jose/v4 @ 2.6.3 → 4.0.5 [Apache-2.0, BSD-3-Clause]
  ↑ github.com/go-sql-driver/mysql @ 1.5.0 → 1.9.0 [MPL-2.0]
  ↑ github.com/gocql/gocql @ 1.6.0 → 1.7.0 [Apache-2.0]
  ↑ github.com/golang-jwt/jwt/v4 @ 4.5.0 → 4.5.2 [MIT]
  - github.com/golang/groupcache @ 0.0.0-20210331224755-41bb18bfe9da
  ↓ github.com/golang/mock @ 1.7.0-rc.1 → 1.6.0 [Apache-2.0]
  - github.com/golang/protobuf @ 1.5.4
  ↑ github.com/google/go-cmp @ 0.6.0 → 0.7.0 [BSD-3-Clause]
  + github.com/google/pprof @ 0.0.0-20250208200701-d0013a598941 [Apache-2.0, BSD-3-Clause]
  ↑ github.com/google/s2a-go @ 0.1.7 → 0.1.9 [Apache-2.0]
  ↑ github.com/googleapis/enterprise-certificate-proxy @ 0.3.2 → 0.3.5 [Apache-2.0]
  ↑ github.com/googleapis/gax-go/v2 @ 2.12.4 → 2.14.1 [BSD-3-Clause]
  ↑ github.com/grpc-ecosystem/grpc-gateway/v2 @ 2.22.0 → 2.26.1 [BSD-3-Clause]
  + github.com/huandu/xstrings @ 1.5.0 [MIT]
  ↑ github.com/jackc/pgservicefile @ 0.0.0-20221227161230-091c0ba34f0a → 0.0.0-20240606120523-5a60cdf6a761 [MIT]
  ↑ github.com/jackc/pgx/v5 @ 5.6.0 → 5.7.2 [MIT]
  ↑ github.com/jackc/puddle/v2 @ 2.2.1 → 2.2.2 [MIT]
  ↑ github.com/jmoiron/sqlx @ 1.3.4 → 1.4.0 [MIT]
  + github.com/json-iterator/go @ 1.1.12 [MIT]
  + github.com/jstemmer/go-junit-report/v2 @ 2.1.0 [MIT]
  + github.com/klauspost/compress @ 1.18.0 [BSD-3-Clause, Apache-2.0, MIT]
  - github.com/konsorten/go-windows-terminal-sequences @ 1.0.1
  ↑ github.com/mailru/easyjson @ 0.7.7 → 0.9.0 [MIT]
  + github.com/maruel/panicparse/v2 @ 2.4.0 [Apache-2.0]
  ↑ github.com/mattn/go-colorable @ 0.1.13 → 0.1.14 [MIT]
  ↑ github.com/mattn/go-runewidth @ 0.0.13 → 0.0.16 [MIT]
  + github.com/mitchellh/copystructure @ 1.2.0 [MIT]
  + github.com/mitchellh/reflectwalk @ 1.0.2 [MIT]
  + github.com/modern-go/concurrent @ 0.0.0-20180306012644-bacd9c7ef1dd [Apache-2.0]
  + github.com/modern-go/reflect2 @ 1.0.2 [Apache-2.0]
  + github.com/munnerz/goautoneg @ 0.0.0-20191010083416-a7dc8b61c822 [BSD-3-Clause]
  ↑ github.com/nexus-rpc/sdk-go @ 0.0.10 → 0.3.0 [MIT]
  + github.com/planetscale/vtprotobuf @ 0.6.1-0.20240319094008-0393e58bdf10 [BSD-3-Clause, MIT]
  ↑ github.com/prometheus/client_golang @ 1.19.1 → 1.21.0 [Apache-2.0, BSD-3-Clause]
  ↑ github.com/prometheus/common @ 0.53.0 → 0.62.0 [Apache-2.0]
  ↑ github.com/prometheus/procfs @ 0.15.0 → 0.15.1 [Apache-2.0]
  ↑ github.com/rcrowley/go-metrics @ 0.0.0-20141108142129-dee209f2455f → 0.0.0-20201227073835-cf1acfcdf475 [BSD-2-Clause-Views]
  ↑ github.com/rivo/uniseg @ 0.2.0 → 0.4.7 [MIT]
  + github.com/shopspring/decimal @ 1.4.0 [MIT]
  ↑ github.com/sirupsen/logrus @ 1.4.2 → 1.9.3 [MIT]
  + github.com/spf13/cast @ 1.7.0 [MIT]
  + github.com/spiffe/go-spiffe/v2 @ 2.5.0 [Apache-2.0]
  ↑ github.com/stretchr/testify @ 1.9.0 → 1.10.0 [MIT]
  ↑ github.com/temporalio/ringpop-go @ 0.0.0-20240718232345-e2a435d149b6 → 0.0.0-20250130211428-b97329e994f7 [MIT]
  ↑ github.com/temporalio/tctl-kit @ 0.0.0-20230328153839-577f95d16fa0 → 0.0.0-20250107205014-58462b03dfb2 [MIT]
  ↑ github.com/uber-common/bark @ 1.0.0 → 1.3.0 [MIT]
  ↑ github.com/uber-go/tally/v4 @ 4.1.17-0.20240412215630-22fe011f5ff0 → 4.1.17 [MIT]
  ↑ github.com/urfave/cli/v2 @ 2.4.0 → 2.27.5 [MIT]
  + github.com/xrash/smetrics @ 0.0.0-20240521201337-686a1a2994c1 [MIT]
  + github.com/zeebo/errs @ 1.4.0 [MIT]
  - go.opencensus.io @ 0.24.0
  + go.opentelemetry.io/auto/sdk @ 1.1.0 [Apache-2.0]
  + go.opentelemetry.io/collector/pdata @ 1.34.0 [Apache-2.0]
  + go.opentelemetry.io/contrib/detectors/gcp @ 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc @ 0.52.0 → 0.59.0 [Apache-2.0]
  ↑ go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp @ 0.52.0 → 0.59.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/exporters/otlp/otlptrace @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/exporters/prometheus @ 0.49.0 → 0.56.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/metric @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/sdk @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/sdk/metric @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/otel/trace @ 1.27.0 → 1.34.0 [Apache-2.0]
  ↑ go.opentelemetry.io/proto/otlp @ 1.2.0 → 1.5.0 [Apache-2.0]
  ↑ go.temporal.io/api @ 1.39.0 → 1.53.0 [MIT, BSD-3-Clause]
  ↑ go.temporal.io/sdk @ 1.27.0 → 1.35.0 [MIT]
  - go.temporal.io/version @ 0.3.0
  ↑ go.uber.org/automaxprocs @ 1.5.3 → 1.6.0 [MIT]
  ↑ go.uber.org/dig @ 1.17.1 → 1.18.0 [MIT]
  ↑ go.uber.org/fx @ 1.22.0 → 1.23.0 [MIT]
  + go.uber.org/mock @ 0.5.0 [Apache-2.0]
  ↑ golang.org/x/crypto @ 0.26.0 → 0.37.0 [BSD-3-Clause]
  ↑ golang.org/x/exp @ 0.0.0-20240531132922-fd00a4e0eefc → 0.0.0-20250218142911-aa4b98e5adaa [BSD-3-Clause]
  ↑ golang.org/x/net @ 0.28.0 → 0.39.0 [BSD-3-Clause]
  ↑ golang.org/x/oauth2 @ 0.22.0 → 0.28.0 [BSD-3-Clause]
  ↑ golang.org/x/sync @ 0.8.0 → 0.13.0 [BSD-3-Clause]
  ↑ golang.org/x/sys @ 0.24.0 → 0.32.0 [BSD-3-Clause]
  ↑ golang.org/x/text @ 0.17.0 → 0.24.0 [BSD-3-Clause]
  ↑ golang.org/x/time @ 0.5.0 → 0.10.0 [BSD-3-Clause]
  ↑ google.golang.org/api @ 0.182.0 → 0.224.0 [BSD-3-Clause]
  ↑ google.golang.org/genproto @ 0.0.0-20240528184218-531527333157 → 0.0.0-20250303144028-a0af3efb3deb [Apache-2.0]
  ↑ google.golang.org/genproto/googleapis/api @ 0.0.0-20240827150818-7e3bb234dfed → 0.0.0-20250303144028-a0af3efb3deb [Apache-2.0]
  ↑ google.golang.org/genproto/googleapis/rpc @ 0.0.0-20240827150818-7e3bb234dfed → 0.0.0-20250303144028-a0af3efb3deb [Apache-2.0]
  ↑ google.golang.org/grpc @ 1.66.0 → 1.72.2 [Apache-2.0]
  - google.golang.org/grpc/cmd/protoc-gen-go-grpc @ 1.3.0
  - google.golang.org/grpc/examples @ 0.0.0-20240531231403-5d7bd7aacb0c
  ↑ google.golang.org/protobuf @ 1.34.2 → 1.36.6 [BSD-3-Clause]
  + modernc.org/cc/v4 @ 4.24.4 [BSD-3-Clause]
  + modernc.org/ccgo/v4 @ 4.20.4 [BSD-3-Clause]
  ↑ modernc.org/gc/v3 @ 3.0.0-20240304020402-f0dba7c97c2b → 3.0.0-20250121204235-2db1fde51ea4 [BSD-3-Clause]
  ↑ modernc.org/libc @ 1.50.9 → 1.55.3 [BSD-3-Clause, MIT]
  ↑ modernc.org/mathutil @ 1.6.0 → 1.7.1 [BSD-3-Clause]
  ↑ modernc.org/memory @ 1.8.0 → 1.8.2 [BSD-3-Clause]
  + modernc.org/opt @ 0.1.4 [BSD-3-Clause]
  ↑ modernc.org/sqlite @ 1.30.0 → 1.34.1 [BSD-3-Clause]
  ↑ modernc.org/strutil @ 1.2.0 → 1.2.1 [BSD-3-Clause]
  ↑ stdlib @ 1.22.6 → 1.25.0 

Summary:
  + 37 packages added
  - 7 packages removed
  ↑ 80 packages upgraded
  ↓ 1 package downgraded

Scanning for vulnerabilities...

∴ Vulnerabilities Found:

github.com/aws/aws-sdk-go v1.55.6 [direct]:
  • CVE-2020-8912 [?]  
    In-band key negotiation issue in AWS S3 Crypto SDK for golang
    Aliases: GHSA-7f33-f4f5-xwgw, GO-2022-0635
    Published: 2024-12-12
  • CVE-2020-8911 [?]  
    CBC padding oracle issue in AWS S3 Crypto SDK for golang
    Aliases: GHSA-f5pg-7wfw-84q9, GO-2022-0646
    Published: 2022-02-11

Vulnerability Summary:
  - 2 have no fix available yet

  2 total vulnerabilities
  Severity: 2 unscored
  All in direct dependencies (can upgrade directly)

Recommended Actions:
  1. Investigate unfixed vulnerabilities - review manually or consider alternatives

Module Deprecations:
  • github.com/aws/aws-sdk-go -> github.com/aws/aws-sdk-go-v2 (https://github.com/aws/aws-sdk-go-v2)
```

```console
$ deputy scan github.com/hashicorp/go-getter

Scanned github.com/hashicorp/go-getter @ main (d879f88)
  Origin: https://github.com/hashicorp/go-getter.git

∴ Vulnerabilities Found:

github.com/ulikunitz/xz v0.5.14 [indirect]:
  • CVE-2025-58058 [MED] (↑ v0.5.15) 
    Leaks memory when decoding a corrupted multiple LZMA archives
    Aliases: GHSA-jc7w-c686-c4v9
    Published: 2025-08-28

golang.org/x/oauth2 v0.7.0 [indirect]:
  • CVE-2025-22868 [HIGH] (↑ v0.27.0) [2 related]
    Improper Validation of Syntactic Correctness of Input vulnerability
    Aliases: GHSA-6v2p-p543-phr9, GO-2025-3488
    Published: 2025-07-18

Vulnerability Summary:
  ! 1 require immediate attention (critical/high severity)
  ↑ 2 can be fixed by upgrading

  2 total vulnerabilities
  Severity: 1 high, 1 medium
  All in indirect dependencies (check dependency tree)

Recommended Actions:
  1. Upgrade modules immediately (critical/high)
      • go get github.com/ulikunitz/xz@v0.5.15
      • go get golang.org/x/oauth2@v0.27.0
      • go mod tidy
```
