# Deputy Policy Framework

Deputy’s core insight is that dependency intelligence should be reusable everywhere: while scanning a repo, diffing SBOMs, fixing vulns, or now intercepting artifact downloads. The `deputy policy` command and the embedded CEL engine make those decisions explicit, auditable, and shareable.

## Goals

- One **policy language** (CEL) for every enforcement point.
- Rich **evaluation context** that combines repo metadata, dependency graphs, OSV findings, SBOM slices, and proxy request details.
- First-class **tooling**: lint, test, bundle, and distribute policies just like code.
- **Composable** actions so a policy can deny a proxy request, emit warnings during `scan`, or annotate SBOMs without duplicating logic.

## Command Surface

| Command | Purpose |
| --- | --- |
| `deputy policy eval --policy policy/block.yaml --input scan.json` | Evaluate a policy bundle against JSON input (any Deputy command can emit JSON for reuse here). |
| `deputy policy test ./policy` | Run table-driven test cases stored alongside policies (see below). |
| `deputy policy bundle --out policy/corp.bundle.json policy/*.yaml` | Package structured bundles for fast loading by other commands. |
| `deputy policy lint policy/*.yaml` | Static checks (unused vars, shadowed identifiers, deprecated helpers). |
| `deputy policy inspect policy.yaml bundle.json` | Show bundle metadata (names, entrypoints) or bundle contents. |
| `deputy policy simulate --policy policy.yaml --input payload.json` | Replay recorded inputs through one or more policies to observe combined decisions before rollout. |
| `deputy policy repl` | Start an interactive CEL playground backed by a `metadata` map for quick experiments. |
| `deputy policy lsp` | Run the policy language server (YAML + CEL authoring). See `docs/policy-lsp.md` for editor wiring. |

Other commands opt into the framework via `--policy` or `--policy-bundle` flags. Examples:

- `deputy scan --policy policy/corp.bundle.json`
- `deputy diff --policy policy/licensing.yaml`
- `deputy proxy serve --config proxy.yaml --policy-bundle policy/corp.bundle.json`
- `deputy sbom --policy policy/sbom.yaml --format json`
- `deputy fix --policy policy/fix.yaml --format json`
- `deputy triage --policy policy/triage.yaml`

Each CLI command emits well-defined entrypoints when `--policy` is provided:

| Command | Entry points emitted |
| --- | --- |
| `deputy scan` | `scan_report`, `scan_vulnerability` |
| `deputy diff` | `diff_report`, `diff_dependency_change`, `diff_vulnerability` |
| `deputy sbom` | `sbom_report`, `sbom_component` |
| `deputy fix` | `fix_plan`, `fix_plan_step` |
| `deputy triage` | `triage_report`, `triage_cluster` |

The `env` object passed to CEL now contains both `command` (e.g., `scan`) and `entrypoint` (e.g., `scan_vulnerability`) so a single policy file can branch on where it is being evaluated.

## Structured Policy Bundles

Policies are authored as structured YAML bundles. Example (`policy/examples/license-allowlist.yaml`):

```yaml
policies:
  - name: block-copyleft-licenses 
    description: Do not allow dependencies with copyleft licenses
    vars:
      forbidden: 
        - "SSPL-1.0"
        - "AGPL-3.0-only"
        - "GPL-3.0"
    rules:
      - action: deny
        when: licenses.exists(l, l in forbidden)
        reason: package carries a forbidden license
      - action: warn
        when: size(licenses) == 0
        reason: package missing license metadata
```

Use `deputy policy lint policy/examples/*.yaml` to ensure the generated CEL compiles, and reference them from any command via `--policy policy/examples/log4shell.yaml`.

### Entry points

Each Deputy **command** exposes one or more **entrypoints**. Policies can declare the entrypoints (and/or commands) they target (`entrypoints: ["..."]`). The runtime prefilters policies using these lists before evaluation. Every evaluation injects `env.command` and `env.entrypoint` so a single policy can branch further if needed.

**Ecosystem identifiers** (used in `request.ecosystem` and commonly in `pkg.ecosystem`): `go`, `npm`, `pypi`, `rubygems`. Use these strings in `ecosystems: [...]` when scoping policies to package managers.

**Entrypoint identifiers** (always use `snake_case` format):
- proxy: `go_artifact_request`, `npm_artifact_request`, `pypi_artifact_request`, `rubygems_artifact_request`
- scan: `scan_report`, `scan_vulnerability`
- diff: `diff_report`, `diff_dependency_change`, `diff_vulnerability`
- sbom: `sbom_report`, `sbom_component`
- fix: `fix_plan`, `fix_plan_step`
- triage: `triage_report`, `triage_cluster`

| Entry point | Triggered by | Input shape |
| --- | --- | --- |
| `go_artifact_request` | `deputy proxy` (Go adapter) | `{request: ArtifactRequest, vulnerabilities: [], sbom?: Component, env: {listener, hostname, entrypoint, time}, config: ProxyPolicyConfig}` |
| `pypi_artifact_request`, `npm_artifact_request` | `deputy proxy` for other ecosystems | Same as above. |
| `scan_report` | `deputy scan` (overall report) | `ScanResult` serialized as a map. |
| `scan_vulnerability` | `deputy scan` (per vulnerability) | `{repo, ref, commit, vulnerability}` |
| `diff_report` | `deputy diff` summary | `{repo, baseRef, targetRef, changes, vulnerabilities}` |
| `diff_dependency_change` | `deputy diff` (per change) | `{repo, baseRef, targetRef, change}` |
| `diff_vulnerability` | `deputy diff` (per vulnerability when scanning enabled) | `{repo, baseRef, targetRef, vulnerability}` |
| `sbom_report` | `deputy sbom` summary | `sbom.Result` metadata (repo, ref, commit, document info). |
| `sbom_component` | `deputy sbom` (per package/component) | `{repo, ref, commit, component}` based on extractor packages. |
| `fix_plan` | `deputy fix` (final plan) | `remediationPlan`. |
| `fix_plan_step` | `deputy fix` (per command/step) | `{plan, step, index}`. |
| `triage_report` | `deputy triage` summary | `triageReport`. |
| `triage_cluster` | `deputy triage` (per top package) | `{target, cluster}`. |

The `deputy policy inspect` command documents all available entrypoints and the fields they expose.

### Actions

Policies return arrays of **action objects**. Each object must include an `action` field and can carry additional metadata:

| Action | Required fields | Optional fields | Effect |
| --- | --- | --- | --- |
| `allow` | `action: "allow"` | `message`, `annotations`, `headers` | Explicitly allow while optionally emitting metadata. |
| `warn` | `action: "warn"`, `reason` | `code`, `annotations`, `remediation` | Non-blocking warning surfaced by the caller (CLI log, HTTP header, etc.). |
| `deny` | `action: "deny"`, `reason` | `status`, `remediation`, `annotations` | Abort the operation. `status` maps to HTTP/CLI status codes. |

`mutate` is reserved but not yet supported by the runtime.

### Policy Ordering & Modes

Policies are evaluated in the order provided by the caller; `deny` actions still take precedence over `warn/allow` in callers that *enforce* actions. A policy can opt into *advisory* mode via `mode: advisory`, which downgrades any `deny` actions from that policy to `warn` so you can canary without blocking. `mutate`, explicit priority, and `requires` hints remain on the roadmap.

`deputy policy simulate` (see command table) replays captured JSON inputs through multiple bundles so you can confirm the combined order of operations before turning a policy from *advisory* into *enforce* mode.

### Helpers & Libraries

Deputy injects a standard library into every CEL environment:

- `osv.has_severity(vulnerability, "CRITICAL")`
- `semver.parse("1.2.3")`
- `licenses.is_forbidden(component, ["AGPL-3.0-only"])`
- `deps.origin()` to retrieve `go.mod`/`package-lock.json` provenance.
- `policy.sigstore_verified(component)` (future).

Libraries live in `internal/policy/functions` and can be imported via CEL macros.

### Optional Types & CEL Extensions

Deputy enables CEL’s optional type system via `cel.OptionalTypes` so policies can gracefully handle missing data (e.g., SBOM fields that only exist for certain ecosystems). Key syntax and helpers you can rely on:

| Feature | Example | Purpose |
| --- | --- | --- |
| Optional field/index | `component.?licenses[?0]` | Returns `optional(license)` if present, `optional.none()` otherwise. |
| `hasValue` / `value` | `component.?licenses[?0].hasValue()` | Check for data before acting. |
| `or` / `orValue` | `request.?module.orValue("unknown")` | Provide fallbacks without guards. |
| `optMap` / `optFlatMap` | `component.?licenses.optMap(l, l.upper())` | Transform optional values. |
| Optional literals | `{?key: request.?module.value()}` | Conditionally set map entries. |

Using optional syntax keeps policies robust even when commands omit certain fields (for example, `sbom_component` entrypoints may not populate `licenses` until SBOM materialization is enabled).

## Evaluation Inputs

Inputs are JSON-*friendly* objects, so you can capture them via `--format json` flags and replay them through `deputy policy eval`. Representative shapes (note how `env` carries operational context like `offline` flags, quota windows, etc):

```jsonc
// go_artifact_request
{
  "request": {
    "ecosystem": "go",
    "module": "github.com/acme/private",
    "version": "v1.5.2",
    "fileType": ".zip",
    "operation": "fetch",
    "client": {"ip": "10.0.0.5", "userAgent": "go/1.21", "principal": "builder-42"}
  },
  "vulnerabilities": [
    {"id": "CVE-2024-9999", "severity": "CRITICAL", "summary": "...", "fixedVersion": "v1.5.3"}
  ],
  "env": {
    "listener": "go-corp",
    "time": "2025-02-01T09:00:00Z",
    "offline": false,
    "quota": {"window": "24h", "bytes": 123456789, "requests": 420}
  }
}
```

```jsonc
// scan_vulnerability
{
  "repo": {"name": "acme/deputy", "ref": "main", "path": "/repo"},
  "dependency": {"purl": "pkg:golang/github.com/gin-gonic/gin@1.9.1", "direct": true},
  "vulnerability": {"id": "GO-2024-1234", "severity": "MEDIUM", "aliases": ["CVE-2024-1234"]},
  "findings": {"files": ["go.mod"], "transitive": false}
}
```

## Testing Policies

Policies live alongside test cases (`*.policytest.json`):

```json
{
  "name": "blocks high severity go modules",
  "entrypoint": "go_artifact_request",
  "policy": "./policy/go-block.yaml",
  "input": "./testdata/go_high.json",
  "want": [
    {"action": "deny", "reason": "High severity vuln(s): CVE-2024-9999"}
  ]
}
```

`deputy policy test` loads every test case, evaluates the policy, and diffs the resulting actions. This mimics table-driven Go tests, enabling policy PRs with automated coverage.

Advanced testing features on the roadmap:

- **Parameterized cases** — reference input templates plus parameter matrices to cover permutations without duplicating fixtures.
- **Property-based fuzzing** — `deputy policy fuzz ./policy` (planned) mutates captured inputs to ensure policies stay stable when fields are missing or maliciously crafted.
- **Coverage export** — the CLI will emit per-entrypoint coverage so you can track which policies protect each stage.
- **Go test integration** — `go test ./policy/...` wrappers let you embed policy assertions directly in the repository’s unit tests.

## Distribution & Bundles

Policies are compiled into bundles for fast loading. Bundles are JSON (or protobuf) documents containing:

- metadata (name, version, authors, description),
- CEL ASTs + type declarations,
- dependency graph (other libraries bundled in),
- optional artifacts (supporting docs, test fixtures).

Other Deputy commands can load a bundle once and reuse it for every request to avoid recompilation overhead.

### Versioning, Upgrades & Drift

- Bundles use semantic versions (`bundle.version = "1.2.3"`). CLI flags like `--policy-require-min-version 1.2.0` help coordinate staged rollouts.
- `schemaVersion` tracks structural changes. When a command encounters a future schema it refuses to start unless `--policy-allow-unstable` is set.
- `deputy policy migrate --from bundle-v1.json --to bundle-v2.json` (planned) will automate AST rewrites or metadata tweaks required by new runtimes.
- `deputy policy inspect --diff old.bundle.json new.bundle.json` summarizes added/removed entrypoints and changed actions to prevent accidental drift.
- Running services expose the active bundle digest via logs/metrics so you can confirm what code is enforcing policies.

## Execution Semantics

- Policies run deterministically. There is a strict CPU + wall-clock budget per evaluation; long-running expressions abort with an error that surfaces to the user and increment `deputy_policy_eval_timeouts_total`.
- Inputs are immutable; mutations must go through the `mutate` helper.
- Actions respect the global precedence described earlier. Callers also log the policy/principal pair responsible for the final decision to aid audits.
- CEL trace/debug output can be toggled via `--policy-trace` to help diagnose unexpected results, or `--policy-profile` to emit flamegraphs for particularly complex bundles.

## Versioning & Backwards Compatibility

- Each policy bundle declares `schemaVersion`. Deputy commands refuse to load bundles with a newer schema unless `--policy-allow-unstable` is set.
- The CEL standard library shims maintain backwards compatibility; new helpers are additive.
- The `deputy policy lint` command warns when using deprecated helpers or fields that will change shape in the next release.

## Roadmap

1. **Policy registry** — publish signed bundles to OCI or Git, referenced via `--policy ghcr.io/acme/deputy-policies:latest`.
2. **IDE support** — go-to-definition and hover docs for YAML + CEL files.
3. **Runtime metrics** — expose per-policy evaluation duration + decision counts for observability.

## Putting It Together

1. Draft CEL policies and tests under `policy/`.
2. Run `deputy policy lint policy/*.yaml` and `deputy policy test ./policy`.
3. Bundle them: `deputy policy bundle --out policy/corp.bundle.json policy/*.yaml`.
4. Reference the bundle from any command:
   - `deputy scan --policy policy/corp.bundle.json`
   - `deputy proxy serve --config proxy.yaml --policy-bundle policy/corp.bundle.json`
   - `deputy diff --policy policy/corp.bundle.json`
5. Capture JSON outputs from commands (`--format json`) to keep policy tests aligned with real-world data.

Deputy now has a single, auditable control plane that powers scans, diffs, SBOMs, fixes, and the new proxy. Policies become reusable “lego bricks” you can snap onto any stage of the SDLC.
