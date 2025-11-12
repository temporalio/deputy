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
| `deputy policy eval --policy policy/block.cel --input scan.json` | Evaluate a policy file against JSON input (any Deputy command can emit JSON for reuse here). |
| `deputy policy test ./policy` | Run table-driven test cases stored alongside policies (see below). |
| `deputy policy bundle --out policy/corp.bundle.json policy/*.cel` | Compile + type-check CEL programs and package them (with metadata) for fast loading by other commands. |
| `deputy policy lint policy/*.cel` | Static checks (unused vars, shadowed identifiers, deprecated helpers). |
| `deputy policy inspect policy.cel bundle.json` | Show CEL metadata (names, entrypoints) or bundle contents. |
| `deputy policy simulate --policy policy.cel --input payload.json` | Replay recorded inputs through one or more policies to observe combined decisions before rollout. |

Other commands opt into the framework via `--policy` or `--policy-bundle` flags. Examples:

- `deputy scan --policy policy/corp.bundle.json`
- `deputy diff --policy policy/licensing.cel`
- `deputy proxy serve --config proxy.yaml --policy-bundle policy/corp.bundle.json`
- `deputy sbom --policy policy/sbom.cel --format json`
- `deputy fix --policy policy/fix.cel --format json`
- `deputy triage --policy policy/triage.cel`

Each CLI command emits well-defined entrypoints when `--policy` is provided:

| Command | Entry points emitted |
| --- | --- |
| `deputy scan` | `scan_report`, `scan_vulnerability` |
| `deputy diff` | `diff_report`, `diff_dependency_change`, `diff_vulnerability` |
| `deputy sbom` | `sbom_report`, `sbom_component` |
| `deputy fix` | `fix_plan`, `fix_plan_step` |
| `deputy triage` | `triage_report`, `triage_cluster` |

The `env` object passed to CEL now contains both `command` (e.g., `scan`) and `entrypoint` (e.g., `scan_vulnerability`) so a single policy file can branch on where it is being evaluated.

## Policy Anatomy

Policies are CEL programs annotated with metadata comments:

```cel
//! policy.name = "go-high-severity-blocker"
//! policy.description = "Block CRITICAL/HIGH vulnerabilities on Go artifacts"
//! policy.entrypoints = ["go_artifact_request", "scan_vulnerability"]

severity_to_block := {"CRITICAL", "HIGH"};
in_scope := request.ecosystem == "go";
vulns := vulnerabilities.filter(v, v.severity in severity_to_block);

in_scope && vulns.size() > 0
  ? [{
      "action": "deny",
      "reason": "High severity vuln(s): " + vulns.map(v, v.id).join(", "),
      "status": 403,
    }]
  : [];
```

### Entry points

Each Deputy command exposes one or more entrypoints. Policies declare which entrypoints they support. Every evaluation injects `env.command` and `env.entrypoint` so a single policy can branch on where it is running.

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

The `deputy policy inspect` command documents all available entrypoints and the fields they expose (pulled straight from Go structs).

### Actions

Policies return arrays of action objects. Each object must include an `action` field and can carry additional metadata:

| Action | Required fields | Optional fields | Effect |
| --- | --- | --- | --- |
| `allow` | `action: "allow"` | `message`, `annotations`, `headers` | Explicitly allow while optionally emitting metadata. |
| `warn` | `action: "warn"`, `reason` | `code`, `annotations`, `remediation` | Non-blocking warning surfaced by the caller (CLI log, HTTP header, etc.). |
| `deny` | `action: "deny"`, `reason` | `status`, `remediation`, `annotations` | Abort the operation. `status` maps to HTTP/CLI status codes. |
| `mutate` | `action: "mutate"`, `patch` | — | JSON merge patch applied by compatible entrypoints (proxy rewrites, fix-plan adjustments). |

Use conditional expressions to include actions only when needed:

```cel
has_forbidden_license := license in forbidden;

(has_forbidden_license
  ? [{
      "action": "deny",
      "reason": license + " is not allowed",
      "remediation": "Replace dependency",
    }]
  : [])
```

Multiple action arrays can be concatenated with `+`; the caller evaluates the final list in order (`deny` short-circuits unless `fail-open` is enabled).

### Policy Ordering, Priority & Modes

To avoid ambiguous outcomes when multiple bundles apply to the same entrypoint:

- Policies declare an optional `policy.priority` metadata value (default `0`). Higher numbers run first.
- Within a policy, CEL `deny/warn/...` helpers execute in the order they appear.
- Callers aggregate actions using the fixed precedence `deny > mutate > warn > allow`. The first deny stops evaluation unless the listener/command is configured with `fail-open`.
- `policy.mode = "advisory"` forces all actions to log/annotate only; `mode = "enforce"` (default) may block or mutate behavior. Advisory policies are perfect for canaries.
- `policy.requires = ["sbom_component"]` can request that upstream callers populate expensive fields (e.g., SBOMs) before evaluation; the proxy honors this by pausing the stream.

`deputy policy simulate` (see command table) replays captured JSON inputs through multiple bundles so you can confirm the combined order of operations before turning a policy from advisory into enforce mode.

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

Additional CEL extensions from `github.com/google/cel-go/ext` (math, URL parsing, regex) can be enabled per bundle; Deputy’s default env includes the optional syntax plus `math`, `strings`, and `encoders` helpers.

Examples:

```cel
//! Applies to go_artifact_request
license := sbom.?component.?licenses[?0].orValue("UNKNOWN");

(license in {"AGPL-3.0-only", "SSPL-1.0"}
  ? [{
      "action": "deny",
      "reason": request.module + " carries forbidden license " + license,
      "remediation": "Use org-approved alternatives.",
    }]
  : [])
```

```cel
//! Enforces approved UUID helper usage
optional_match := request.?module
  .optMap(m, m.startsWith("github.com/google/uuid"))
  .orValue(false);

(!optional_match && request.ecosystem == "go" && request.module.contains("uuid")
  ? [{
      "action": "deny",
      "reason": "Use github.com/google/uuid already vendored in the repo",
      "remediation": "Remove " + request.module + " from go.mod and reuse the shared helper.",
    }]
  : [])
```

Using optional syntax keeps policies robust even when commands omit certain fields (for example, `sbom_component` entrypoints may not populate `licenses` until SBOM materialization is enabled).

## Evaluation Inputs

Inputs are JSON-friendly maps so you can capture them via `--format json` flags and replay them through `deputy policy eval`. Representative shapes (note how `env` carries operational context like `offline` flags and quota windows):

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
  "policy": "./policy/go-block.cel",
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

## Integration Examples

1. **Proxy severity blocker** — same CEL snippet from `PROXY.md`. Denies downloads when severity ≥ threshold.
2. **Scan drift guard**:

```cel
//! policy.entrypoints = ["diff_dependency_change"]
(dependency.direct && dependency.newVersion.semver() < dependency.oldVersion.semver()
  ? [{
      "action": "deny",
      "reason": "Direct dependency downgrades require review",
      "remediation": "Run `deputy diff --explain` and attach approval.",
    }]
  : [])
```

3. **SBOM license reporter**:

   ```cel
   //! policy.entrypoints = ["sbom_component"]
   warn when licenses.is_forbidden(component, ["SSPL-1.0"]) {
     reason: component.name + " uses SSPL",
     annotations: {"owner": "legal"}
   }
   ```

4. **Fix plan guardrail**:

```cel
//! policy.entrypoints = ["fix_plan_step"]
(step.kind == "remove" && plan.context.branch == "main"
  ? [{
      "action": "deny",
      "reason": "Cannot remove dependencies on main",
      "remediation": "Create a feature branch.",
    }]
  : [])
```

## Core Governance Use Cases

The first wave of policy bundles should focus on high-value, low-regret controls:

- **Critical-vuln gate** — block artifacts (or scan findings) with CRITICAL/HIGH severity alerts unless a remediation version exists and is already in use. Works equally well in the proxy (`go_artifact_request`) and during `deputy scan`.
- **License guard** — flag or deny dependencies whose licenses fall outside an approved list (GPL, SSPL, AGPL, etc.). When paired with the proxy this keeps restricted code out of Git entirely.
- **Package consolidation** — enforce canonical utility libraries (`uuid`, `logging`, `http clients`) by denying duplicate packages and suggesting the org-standard equivalents.
- **Deprecated module ban** — maintain allow/deny lists (e.g., no `logrus` after migrating to `zerolog`) and surface remediation steps right in the policy.
- **Version floor** — ensure direct dependencies never downgrade below the latest patched release by comparing versions with `semver.parse` and other helpers.

Because CEL entrypoints share the same schema across commands, a single policy file can cover both CLI workflows and proxy enforcement, ensuring engineers get the same guidance whether they run `deputy scan` locally or fetch dependencies through the proxy.

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
2. **Interactive editor** — `deputy policy repl` for quick CEL experimentation with live inputs.
3. **IDE support** — go-to-definition and hover docs for CEL files (via `gopls` + `cel-spec` metadata).
4. **Runtime metrics** — expose per-policy evaluation duration + decision counts for observability.

## Putting It Together

1. Draft CEL policies and tests under `policy/`.
2. Run `deputy policy lint policy/*.cel` and `deputy policy test ./policy`.
3. Bundle them: `deputy policy bundle --out policy/corp.bundle.json policy/*.cel`.
4. Reference the bundle from any command:
   - `deputy scan --policy policy/corp.bundle.json`
   - `deputy proxy serve --config proxy.yaml --policy-bundle policy/corp.bundle.json`
   - `deputy diff --policy policy/corp.bundle.json`
5. Capture JSON outputs from commands (`--format json`) to keep policy tests aligned with real-world data.

Deputy now has a single, auditable control plane that powers scans, diffs, SBOMs, fixes, and the new proxy. Policies become reusable “lego bricks” you can snap onto any stage of the SDLC.
