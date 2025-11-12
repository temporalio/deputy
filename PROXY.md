# Deputy Proxy Design

## Why a Proxy?

Software composition analysis is reactive unless you gate artifacts before they land in a repo or build cache. The `deputy proxy` command closes that gap by running ecosystem-aware HTTP proxies (Go module proxy today, PyPI/npm tomorrow) that:

- sit transparently between the developer/build system and the public registry,
- enrich every request with Deputy’s inventory + vulnerability intelligence, and
- evaluate CEL policies before an artifact is streamed downstream.

This document describes how the proxy command is structured, how it is configured, and how it composes with the forthcoming CEL policy engine (`POLICY.md`).

## Command Surface

| Command | Purpose |
| --- | --- |
| `deputy proxy serve --config proxy.yaml` | Launch one or more proxies described in the config file (multiple listeners are supported). |
| `deputy proxy check --config proxy.yaml` | Validate the config, verify upstream reachability, and dry‑run policies using sample requests. |
| `deputy proxy template --ecosystem go` | Emit a starter config section for a given ecosystem. |
| `deputy proxy inspect --url https://… --config proxy.yaml` | Run a single request through normalization + policy evaluation + upstream fetch without binding a port (great for CI). |

All proxy subcommands accept the global logging flags, `--trace-http` for verbose request logs, and `--policy-bundle` to point at an explicit policy bundle instead of the one referenced by the config.

## High-Level Architecture

```
┌────────────────────┐        ┌──────────────────┐        ┌─────────────────┐
│ HTTP Listener(s)   │ ───▶  │ Ecosystem Adapter │ ───▶  │ Policy Pipeline │
└────────────────────┘        └──────────────────┘        └─────────────────┘
          │                               │                         │
          ▼                               ▼                         ▼
   Metrics/Tracing           Deputy Inventory / OSV         Upstream Fetcher

```

1. **Listener** — a thin HTTP server per `listen` entry in the config. Every request is wrapped in a cancellable context with per-ecosystem deadlines.
2. **Ecosystem adapter** — normalizes HTTP paths into a canonical `ArtifactRequest` (module name, version, file type, metadata). Each adapter is responsible for translating between registry-specific semantics (e.g., `@v/list` for Go, simple filenames for PyPI).
3. **Policy pipeline** — materializes the right evaluation input, runs CEL policies, and returns an `allow | warn | deny | mutate` decision. Policies can introspect scan data, OSV matches, SBOM snippets, repo metadata, and custom config knobs.
4. **Upstream fetcher** — issues the upstream HTTP request once the policy allows it, streams the response body back to the caller, and optionally caches artifacts for subsequent requests.

## Request Lifecycle

1. **Normalize** — adapter parses the request into an `ArtifactRequest`:
   ```go
   type ArtifactRequest struct {
       Ecosystem string            // e.g. "go", "pypi"
       Module    string            // `github.com/foo/bar`
       Version   string            // `v1.2.3` or normalized semver
       FileType  string            // `.zip`, `.mod`, `.info`, wheel, tarball, etc.
       Operation string            // fetch, list, metadata
       Client    ClientMetadata    // IP, auth header hash, Go env, build ID
       Hints     map[string]string // adapter-specific fields
   }
   ```
2. **Enrich** — Deputy’s existing inventory + OSV code is reused to attach vulnerability data. The proxy never shells out to the Go toolchain; it uses `internal/inventory` for parsing and `internal/remediation` for upgrade hints when needed.
3. **Policy evaluation** — the CEL engine receives `{request, inventory, osv, config}` and must return at least one decision (see `POLICY.md`).
4. **Decision**:
   - `allow` — continue to upstream fetch, stream bytes back, update optional cache.
   - `warn` — log + emit structured warning headers (`X-Deputy-Warning`) but still forward.
   - `deny` — short-circuit with HTTP 403/451 plus JSON error body.
   - `mutate` — adapters can swap upstream endpoints (e.g., redirect to an internal mirror) or pin versions before fetching.
5. **Observe** — every request emits structured logs plus OTEL traces/metrics (latency, policy decision counts, upstream errors, block reasons). Health endpoints (`/-/healthy`, `/-/ready`) expose aggregated status for K8s deployments.

## Configuration Model

The config file is YAML or JSON (same schema). Shape:

```yaml
apiVersion: proxy.deputy.sh/v1alpha1
kind: ProxyConfig
listeners:
  - name: go-corp
    bind: ":8080"
    ecosystems: ["go"]
    upstream: https://proxy.golang.org
    cacheDir: ~/.cache/deputy/proxy/go
    decisionCache:
      memoryEntries: 20000        # L1 cache per process
      shared:
        kind: redis               # redis | valkey | none
        url: redis://cache.internal:6379/0
        ttl: 10m
    timeout: 12s
    policies:
      - bundle: policy/controls.bundle.json # produced by `deputy policy bundle`
        entrypoints:
          - go_artifact_request
        priority: 100
        mode: enforce              # enforce | advisory (logs only)
    block:
      severity: ["CRITICAL", "HIGH"]
      whenOffline: fail-open    # or fail-closed
    sbom:
      materialization: policy-driven   # eager | policy-driven | disabled
      cacheDir: ~/.cache/deputy/proxy/go/sbom
    osv:
      mirror: file:///var/cache/osv
      refreshInterval: 6h
    principal:
      header: X-Builder-ID       # override client.principal derived from auth
    transforms:
      rewriteModulePaths:
        - match: ^github\.com/acme/internal/(.+)$
          replace: private.ghe.io/acme/$1
    rateLimit:
      requestsPerSecond: 500
      burst: 150
    policyReload:
      watch: true
      interval: 30s
  - name: npm-sandbox
    bind: ":8081"
    ecosystems: ["npm"]
    upstream: https://registry.npmjs.org
    auth:
      basic:
        username: proxy
        passwordFromEnv: NPM_PROXY_PASSWORD
      upstream:
        bearerTokenFromEnv: NPM_MIRROR_TOKEN
        mtls:
          certFile: /etc/deputy/creds/npm-proxy.crt
          keyFile: /etc/deputy/creds/npm-proxy.key
          caFile: /etc/deputy/creds/npm-rootca.crt
        ssh:
          keyFromEnv: NPM_GIT_SSH_KEY     # for git+ssh package sources
          knownHostsFile: /etc/ssh/ssh_known_hosts
    adapter:
      strict: false              # pass through unrecognized endpoints
```

Key ideas:

- **Multiple listeners**: one binary handles several ecosystems/ports.
- **Per-listener policy stack**: each listener references one or more policy bundles and declares the entrypoints that should run. Bundles can be shared across listeners.
- **Caching**: multi-tier (in-memory, disk, optional Redis/Valkey) caches for both artifacts and policy decisions. Go proxy follows `GOMODCACHE` semantics; PyPI/npm caches store the raw tarball/wheel.
- **Transforms**: lightweight rewrites (strip `.zip`, add module suffixes) before hitting upstream.
- **Auth**: inbound (clients) and outbound (upstream) credentials, with optional principal extraction for multi-tenant policy routing.
- **Rate limits**: per-listener token buckets protect upstream registries and enable per-team quotas.

### Private Registry & Git Authentication

- **mTLS** — specify cert/key/CA bundles per upstream. The proxy pins certificates and rotates them without restart by watching the files.
- **SSH** — for ecosystems that fall back to `git+ssh` (npm, PyPI), point at SSH keys stored in env vars or secret files. Known-hosts enforcement prevents MITM attacks.
- **Token injection** — bearer/PAT tokens are stored in env variables or external secret managers; adapters insert them as needed per request.
- **Per-upstream auth blocks** — each upstream entry may define `auth` overrides, so a proxy that fans out to multiple mirrors can use separate credentials for each.

## Performance, Caching & Latency Budgets

Inline vulnerability lookups plus policy evaluation introduce latency, so the proxy includes several mitigation layers:

1. **Decision caches** — L1 in-memory maps (module+version+policy hash) with TTLs, and optional L2 shared caches (Redis/Valkey) so multi-instance fleets reuse results. Cache entries store `{decision, reason, headers, timestamp}` so a deny surfaces instantly.
2. **Artifact caches** — per-ecosystem directories (Go module cache semantics, npm tarball cache, PyPI wheel cache) plus integrity hashes. Cache hits bypass upstream entirely.
3. **Fast paths** — well-known clean artifacts (e.g., Go stdlib, corporate allowlists) short-circuit enrichment and only emit audit logs.
4. **Prefetch/prewarm** — `deputy proxy check --prewarm popular.txt` can scan an allowlist of modules ahead of time to fill caches before CI/CD spikes.
5. **Metrics** — `deputy_proxy_policy_eval_ms` and `deputy_proxy_request_latency_ms` expose percentiles; alerts can trigger when p95 crosses SLO targets (default 150 ms for metadata, 500 ms for archives).

Adapters enforce deadlines (`context.WithTimeout`) so that OSV lookups or policy evaluation cannot stall the upstream fetch pipeline. When caches are unavailable the proxy can fall back to direct evaluation but will emit warnings so operators know latency may spike.

## Policy Ordering, Priority & Modes

Multiple policies may run for a single listener. The evaluator follows a deterministic order:

1. Sort policies by `priority` (higher first; default 0).
2. Within a policy, preserve the CEL emission order.
3. Aggregate actions with the precedence `deny > mutate > warn > allow`. The first deny stops evaluation unless the listener is configured with `fail-open`.

Policy metadata supports:

- `mode: enforce | advisory` — advisory policies always log (and emit headers) but never block.
- `priority` — tie-breaker for stacking multiple bundles.
- `simulate` flag via CLI (`--policy-simulate <id>`) to run policies side-by-side and compare actual outcomes (e.g., canaries before rollout).

A forthcoming `deputy policy simulate` command loads the same bundle list used by a listener, plays captured request logs (`deputy proxy inspect --record`), and highlights conflicts before production rollout.

## Ecosystem Adapters

Adapters live under `internal/proxy/<ecosystem>` and implement a common interface:

```go
type Adapter interface {
    CanHandle(*http.Request) bool
    Normalize(*http.Request) (*ArtifactRequest, error)
    UpstreamURL(*ArtifactRequest, *Config) (string, error)
    Materialize(*ArtifactRequest, io.Reader) (*inventory.Package, error)
    DefaultPolicies() []string
}
```

The initial adapters:

1. **Go Module Proxy** — replicates the behavior of `proxy.golang.org`. It understands `@latest`, `@v/list`, `.info`, `.mod`, `.zip`, and pseudo-versions. It can optionally read modules from private mirrors by chaining upstream URLs.
2. **PyPI** — focuses on `simple/` HTML indices and direct wheel/tarball fetches. Normalization maps both `simple/pkg/` and `packages/...` URLs into a single `ArtifactRequest`.
3. **npm** — intercepts `/<pkg>` (metadata) and `/<pkg>/-/<pkg>-<version>.tgz` downloads. Handles scoped packages (`@scope/pkg`).

Adding a new adapter mainly requires request parsing + upstream URL mapping; the policy + enrichment layers remain shared.

### Adapter Guardrails

- **Read fetch-first** — initial releases only proxy GET/HEAD traffic. Publish flows (`go mod upload`, npm `publish`, PyPI `twine upload`) are explicitly blocked until we implement signed write paths.
- **Strict vs. permissive** — `adapter.strict: false` tells the proxy to pass through unknown endpoints untouched (log-only). Setting it to `true` enforces full normalization and rejects unsupported verbs early.
- **Feature matrix** — each adapter ships with a documented coverage table (e.g., npm dist-tags, PyPI pre-release filters). Unsupported combinations surface warnings plus hints to fall back to upstream.
- **Ecosystem tests** — adapters include golden fixtures under `internal/proxy/<eco>/testdata` plus policy tests referencing real traces so regressions are caught in CI.

## CEL Policy Integration

Every proxy decision flows through the CEL engine described in `POLICY.md`. The proxy supplies the following input map:

```cel
{
  "request": ArtifactRequest,
  "vulnerabilities": [Vulnerability],          // enriched via OSV before policy evaluation
  "sbom": SBOMComponent?,          // produced lazily for archive downloads
  "config": ProxyPolicyConfig,     // severity lists, allowlists, etc.
  "env": {
    "listener": "go-corp",
    "hostname": "...",
    "entrypoint": "go_artifact_request",
    "time": timestamp(),
    "offline": bool,
    "quota": {
      "principal": "builder-42",
      "window": "24h",
      "bytes": 123456789,
      "requests": 420
    }
  }
}
```

Policies can either return a single decision or an array. Decisions look like:

```json
{
  "action": "deny",
  "reason": "CVE-2024-1234 severity=CRITICAL",
  "status": 403,
  "headers": {"X-Deputy-Blocked-By": "corp-vuln-policy"}
}
```

`deputy proxy serve` aggregates decisions across all matching entrypoints (first `deny` wins unless `fail-open` is configured).

### Common Policy Scenarios

These are the day-one use cases we expect most deployments to enable:

1. **Critical vulnerability blocks** — load `vulnerabilities` from OSV, compare severities against the listener’s guardrail (`block.severity`), and `deny` any module with unfixed CRITICAL/HIGH vulns. The HTTP response can link directly to `deputy fix` upgrade instructions.
2. **License enforcement** — combine SBOM metadata or `request.module` allowlists with CEL helpers like `licenses.is_forbidden` to keep GPL/SSPL code out of repos that disallow it.
3. **Package duplication prevention** — ensure teams use approved stdlib helpers instead of pulling additional UUID/logging libraries by checking `request.module` against an allowlist and emitting `deny` with remediation text (“use `github.com/google/uuid` already vendored in repo”).
4. **Pinned dependency sets** — policies can enforce `version` windows (e.g., no downgrades below a patched release) by comparing `request.version` or the SBOM component’s `effectiveVersion`.
5. **Org-specific mirrors** — `mutate` the upstream URL to steer certain packages to golden mirrors (e.g., internal forks of `logrus`) ensuring reproducibility.

Because these scenarios are expressed in CEL, the exact same policies can be reused by `deputy scan` and `deputy diff` to keep CLI feedback aligned with proxy enforcement.

Example license gate using CEL optional syntax (enabled by default):

```cel
license := sbom.?component.?licenses[?0].orValue("UNKNOWN");

(license in {"SSPL-1.0", "AGPL-3.0-only"}
  ? [{
      "action": "deny",
      "reason": request.module + " carries forbidden license " + license,
      "remediation": "Replace with org-approved library.",
    }]
  : [])
```

Example “prefer existing UUID helper” policy:

```cel
(request.ecosystem == "go" &&
 request.module.contains("uuid") &&
 request.module != "github.com/google/uuid"
  ? [{
      "action": "deny",
      "reason": "Use github.com/google/uuid already provided by platform",
      "remediation": "Reuse the shared helper instead of adding " + request.module,
    }]
  : [])
```

## Observability & Ops

- **Logs**: structured JSON with `listener`, `module`, `version`, `policy_action`, `policy_id`, `duration_ms`, `cache_hit`.
- **Metrics**: exported via OTEL/Prometheus — `deputy_proxy_requests_total`, `deputy_proxy_policy_denies_total`, `deputy_proxy_upstream_latency_seconds`, `deputy_proxy_cache_size_bytes`, `deputy_proxy_policy_eval_ms`, `deputy_proxy_rate_limit_drops_total`, etc.
- **Tracing**: optional OTEL spans around normalization, policy evaluation, upstream fetch, and streaming to clients.
- **Health**: `/-/healthy` (process up) and `/-/ready` (upstream probes + cache status). `deputy proxy check` uses the same readiness checks.
- **Cost & quota telemetry**: per-principal counters (derived from auth headers or mTLS certs) back fuel-showback dashboards and alerting.

## SBOM Materialization & Cost Controls

SBOM extraction can be expensive, so it is opt-in and policy-aware:

- `materialization: eager | policy-driven | disabled` controls whether every archive download is unpacked, only when a policy references `sbom_component`, or never.
- Artifacts stream to temp files with content hashing; SBOM metadata is cached by `(ecosystem, module, version, hash)` so repeated requests reuse the same analysis.
- Policies can demand SBOM data by returning `mutate { patch: {"sbom": {"require": true}} }`; the proxy responds by pausing the upstream stream, materializing the SBOM, and resuming if allowed.
- `sbom.shallow: true` lets adapters capture only top-level metadata (name, version, hash) when full dependency walks are unnecessary.

## Artifact Signing & Attestations

While SBOMs describe contents, signature verification ensures provenance:

- **Sigstore/Cosign** — adapters can declare `signing:
  required: true` plus Rekor URLs. After downloading an artifact the proxy pauses response streaming, runs signature verification, and only resumes if the signature matches trusted identities.
- **PGP/Legacy** — PyPI’s `.asc` and npm’s `integrity` hashes are verified during normalization; CEL policies can inspect `request.signing` metadata (issuer, certificate, SANs) before allowing the download.
- **Policy hooks** — verification results are attached to the policy input (`request.signing.verified bool`, `request.signing.identity string`). Policies can require certain issuers or block unsigned artifacts.
- **Attestation fetching** — optional `signing.attestations` list fetches SLSA/SBOM attestations and turns them into CEL data structures for deeper inspection.
- **Failure handling** — verification errors surface as `deny` actions with `status=412` by default; `fail-open` can override this when running in learning mode.

## Authorization, Principals & Multi-Tenancy

- Inbound auth supports basic auth, bearer tokens, mTLS, or trusted headers from an upstream identity proxy. Each request is annotated with `client.principal`.
- Policies can branch on principals (`request.client.principal in {"team-a", "team-b"}`) to apply distinct rules or allowlists.
- Per-listener `principalMappings` translate certificates or JWT claims into canonical principals.
- Metrics and logs include `principal`, enabling rate limits or blocklists per tenant. A future `deputy quota` command can read these counters for chargeback.
- Outbound auth handles private registries or mirrors via bearer tokens, mTLS certs, or PATs sourced from env vars / secret stores so proxied fetches remain transparent.

## Offline / Air-Gapped Operation

- Configure `osv.mirror` to point at `file://` paths generated via `deputy osv sync` (CLI that periodically mirrors OSV/GHSA data into tarballs).
- When the proxy detects `env.offline == true`, policies can automatically downgrade severity or switch to allowlists.
- Health checks differentiate between “upstream offline” and “mirror stale” so operators know when to resync data.

## Rate Limiting & Upstream Protection

- Each listener exposes a token-bucket rate limiter. Policies can override the limiter per principal (e.g., CI pools vs. laptops).
- `429` responses include `Retry-After` headers derived from the limiter state. Logs capture `rate_limit_key` for auditing.
- Optional `burst` tuning allows short spikes without overwhelming upstream mirrors.

## Cost Attribution & Quota Exports

- Per-principal metrics feed a new `deputy quota` CLI:
  - `deputy quota export --since 24h --format csv` emits rows containing listener, principal, ecosystem, bytes streamed, cache hit %, policy denies, and rate-limit drops.
  - `deputy quota diff --base last-week.json --head today.json` highlights anomalous increases.
- Exports can target stdout, S3/GCS, BigQuery, or any OTLP-compatible sink, making it easy to plug into billing dashboards.
- Policies can consult rolling usage windows (supplied via the input `env.quota`) to tighten rules automatically when a team exceeds its allocation.

## Write Path Security (Future)

The initial proxy release is fetch-only, but the design anticipates secure publish flows:

- **Explicit opt-in** — `writePaths: ["npm.publish", "pypi.upload"]` gates which verbs are allowed. Everything else remains read-only.
- **Sigstore signing** — clients must attach Sigstore bundles (or corporate signing equivalents). The proxy validates signatures, stores them in an append-only log, and only forwards to upstream if verification succeeds.
- **Change approvals** — denied publish attempts emit structured events that can be routed to ChatOps/ticketing. Accepted publishes create immutable audit records (`deputy audit export`) capturing artifact hash, principal, policy decisions, and upstream response IDs.
- **Replay protection** — per-artifact nonces and Rekor integration prevent replayed publish requests.
- **Sandbox enforcement** — policies can require that publish requests originate from dedicated principals (CI/CD) or specific IP ranges.

This phased plan ensures that when Deputy eventually proxies write traffic the security posture is even stronger than the upstream registries.

## Policy Reload & Drift Detection

- `policyReload.watch: true` enables fsnotify-based hot reloads of bundles; listeners atomically swap evaluators without dropping connections.
- `deputy proxy serve --policy-digest` prints the active bundle fingerprint so you can compare against Git/OCI digests.
- `deputy policy diff bundleA bundleB` (future) highlights semantic changes before rollout.


## Failure Modes

- **OSV/policy bundle offline** — configurable `fail-open` or `fail-closed`. Fail-open still logs warnings and can optionally return `Retry-After`.
- **Upstream outage** — the proxy surfaces 502 and optionally falls back to mirror URLs defined in the config (`fallbackUpstreams` list).
- **Slow clients** — server enforces per-request deadline + response streaming with backpressure; instrumentation reveals which step stalls.

## Implementation Phases

1. **Phase 1 (MVP)** — Go adapter, policy framework integration, in-memory caches, structured logging, health probes, deny policies for critical/high severities.
2. **Phase 2 (Production)** — PyPI/npm adapters, fail-open/fail-closed knobs, OTEL metrics/traces, tiered caches, rate limiting, `policy simulate`.
3. **Phase 3 (Enterprise)** — multi-tenant isolation, distributed caches, policy registry (OCI/Git), inline remediation hints, artifact signing, cost attribution exports.

## Roadmap

1. **Inline patching** — combine `deputy fix` plans with the proxy so blocked artifacts suggest the exact upgrade command in the HTTP error payload.
2. **Artifact attestations** — verify Sigstore/Rekor entries before forwarding.
3. **Enterprise approvals** — connect policy actions to ticketing/ChatOps workflows so a deny can auto-open a security review.
4. **Multi-leg proxies** — allow chaining `deputy proxy` instances (edge vs. build farm) with signed decision tokens so inner layers can trust outer policy results.

## Quick Start

1. Create `proxy.yaml` using `deputy proxy template --ecosystem go > proxy.yaml`.
2. Customize upstream URLs, severity guardrails, and policy bundle references.
3. Write CEL policies (see `POLICY.md`) and bundle them: `deputy policy bundle --out policy/corp.bundle.json policy/*.cel`.
4. Run `deputy proxy check --config proxy.yaml`.
5. Launch the proxy: `deputy proxy serve --config proxy.yaml`.
6. Point `GOPROXY` (and later `PIP_INDEX_URL`, `npm config set registry`) at the Deputy listener.

With that, Deputy becomes both a scanner _and_ an enforcement point, using the same inventory intelligence across the SDLC.
