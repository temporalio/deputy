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
┌──────────────────┐       ┌───────────────────┐       ┌─────────────────┐
│ HTTP Listener(s) │ ───▶  │ Ecosystem Adapter │ ───▶  │ Policy Pipeline │
└──────────────────┘       └───────────────────┘       └─────────────────┘
          │                         │                           │
          ▼                         ▼                           ▼
   Metrics/Tracing         Deputy Inventory / OSV        Upstream Fetcher

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

To spin up a PyPI proxy, run `deputy proxy template --ecosystem pypi > proxy.yaml` and update the `upstream` (defaults to `https://pypi.org`). Policies receive `pypi_artifact_request` evaluations with the parsed package/version plus any OSV/metadata enrichments.

Similarly, `deputy proxy template --ecosystem npm` scaffolds an npm/Node proxy config rooted at `https://registry.npmjs.org`, emitting `npm_artifact_request` payloads so you can block vulnerable or disallowed tarballs before they hit your CI caches.

`deputy proxy template --ecosystem rubygems` does the same for the RubyGems ecosystem, wiring up `/api/...` metadata calls and `/downloads/*.gem` files to the policy engine via `rubygems_artifact_request`.

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
2. **PyPI** — proxies `simple/` index traffic plus `packages/...` downloads. It extracts package versions from wheel/sdist filenames, enriches requests with OSV results for the `PyPI` ecosystem, and allows policies to reject releases (e.g., block AGPL-licensed or vulnerable packages).
3. **npm** — intercepts registry metadata (`/<pkg>`, `/-/package/...`) and tarball downloads (`/<pkg>/-/<pkg>-<version>.tgz`). Handles scoped packages (`@scope/pkg`), enriches with OSV for the npm ecosystem, and allows license/semver policies before tarballs are streamed.
4. **RubyGems** — proxies `api/v1/...` metadata endpoints plus `/downloads/<gem>-<version>.gem` artifacts, populating vulnerability/license context so policies can gate individual gem versions.

Adding a new adapter mainly requires request parsing + upstream URL mapping; the policy + enrichment layers remain shared.

### Adapter Guardrails

- **Read fetch-first** — initial releases only proxy GET/HEAD traffic. Publish flows (`go mod upload`, npm `publish`, PyPI `twine upload`) are explicitly blocked until we implement signed write paths.
- **Strict vs. permissive** — `adapter.strict: false` tells the proxy to pass through unknown endpoints untouched (log-only). Setting it to `true` enforces full normalization and rejects unsupported verbs early.
- **Feature matrix** — each adapter ships with a documented coverage table (e.g., npm dist-tags, PyPI pre-release filters). Unsupported combinations surface warnings plus hints to fall back to upstream.
- **Ecosystem tests** — adapters include golden fixtures under `internal/proxy/<eco>/testdata` plus policy tests referencing real traces so regressions are caught in CI.

### npm Proxy Hands-On Example

You can gain confidence in the npm adapter without installing Node locally by driving it through Docker’s `node:20` image. The steps below were executed verbatim and rely only on Go, Docker Desktop (or another daemon exposing `host.docker.internal`), and the Deputy source tree.

1. **Create a throwaway workspace** — this holds the proxy config, CEL policies, and downloaded tarballs:

   ```bash
   tmpdir=$(mktemp -d /tmp/deputy-npm-proxy-XXXXXX)
   mkdir -p "$tmpdir/policies" "$tmpdir/artifacts"

   cat <<EOF > "$tmpdir/proxy.yaml"
   listeners:
     - name: npm-proxy
       bind: ":8082"
       ecosystems: ["npm"]
       upstream: https://registry.npmjs.org
       policies:
         - $tmpdir/policies/allow-all.yaml
   EOF

cat <<'EOF' > "$tmpdir/policies/allow-all.yaml"
apiVersion: policy.deputy.sh/v1alpha2
kind: PolicyBundle
policies:
  - name: allow-all
    rules:
      - action: allow
        when: true
EOF
   ```

2. **Launch the proxy** and keep the PID so you can shut it down later:

   ```bash
   go run . --log-level=info proxy serve --config "$tmpdir/proxy.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

   When the listener is ready `proxy.log` shows `proxy listener starting … ecosystem=npm upstream=https://registry.npmjs.org`.

3. **Happy path** — use Dockerized npm to fetch a tarball through the proxy (Mac/Windows use `host.docker.internal`; Linux can add `--network host` instead):

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     -e NPM_CONFIG_STRICT_SSL=false \
     node:20 \
     npm pack lodash@4.17.21 --registry http://host.docker.internal:8082
   ```

   Expected result: `lodash-4.17.21.tgz` appears under `$tmpdir/artifacts`, npm prints the usual tarball summary, and `proxy.log` contains an allow decision for the request.

4. **Add a blocking policy** — deny `left-pad` and restart the proxy with the policy overlay:

   ```bash
   cat <<'EOF' > "$tmpdir/policies/block-leftpad.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: block-leftpad
       rules:
         - action: deny
           when: request.package == "left-pad"
           reason: "blocked package (left-pad)"
           status: 403
           headers:
             X-Deputy-Policy: block-leftpad
   EOF

   kill $(cat "$tmpdir/proxy.pid")
   go run . --log-level=info proxy serve \
     --config "$tmpdir/proxy.yaml" \
     --policy "$tmpdir/policies/block-leftpad.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

5. **See the policy fire** — another Dockerized npm invocation now fails with `E403` and the proxy emits structured deny logs:

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     -e NPM_CONFIG_STRICT_SSL=false \
     node:20 \
     npm pack left-pad@1.3.0 --registry http://host.docker.internal:8082
   ```

   Output excerpt:

   ```
   npm error code E403
   npm error 403 403 Forbidden - GET http://host.docker.internal:8082/left-pad
   npm error 403 … forbidden by your security policy …
   ```

   A parallel `curl -i http://127.0.0.1:8082/left-pad` shows the proxy response body `blocked package (left-pad)` plus the `X-Deputy-Policy: block-leftpad` header so you can double-check what a CLI would receive.

6. **Cleanup** when you are done:

   ```bash
   kill $(cat "$tmpdir/proxy.pid")
   rm -rf "$tmpdir"
   ```

These copy/pasteable commands make it easy for new users to exercise both the allow and deny flows before wiring the proxy into npm, pnpm, or yarn on their workstations.

### Proxy Quick Runner

If you already have Deputy installed locally, the fastest way to try the proxy is to let the CLI spin up a temporary listener and wrap your package manager. Each ecosystem now has a dedicated subcommand that accepts the real tool invocation after `--`:

- `deputy proxy go -- go mod download golang.org/x/text@v0.14.0`
- `deputy proxy npm -- npm pack lodash@4.17.21`
- `deputy proxy pypi -- pip download requests==2.31.0 --no-deps`
- `deputy proxy rubygems -- gem fetch bundler -v 2.4.22`

> The npm wrapper also covers Yarn and pnpm because they respect `NPM_CONFIG_REGISTRY` out of the box.

Under the hood these commands launch an in-process proxy bound to `127.0.0.1`, set the right env vars (`GOPROXY`, `NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL`, `GEMRC`, etc.), run your command, then tear everything down. You can still pass extra flags before `--`, e.g. `--policy corp.yaml` or `--upstream https://custom.mirror` to mirror production settings. The manual Docker flows below remain available when you want to see every moving piece explicitly or script the experience into CI.

### PyPI Proxy Hands-On Example

The same pattern works for Python without polluting your host interpreter. This example uses Docker’s `python:3.12` image, but any image with `pip` installed will behave the same way.

1. **Create a workspace and config**:

   ```bash
   tmpdir=$(mktemp -d /tmp/deputy-pypi-proxy-XXXXXX)
   mkdir -p "$tmpdir/policies" "$tmpdir/artifacts"

   cat <<EOF > "$tmpdir/proxy.yaml"
   listeners:
     - name: pypi-proxy
       bind: ":8081"
       ecosystems: ["pypi"]
       upstream: https://pypi.org
       policies:
         - $tmpdir/policies/allow-all.yaml
   EOF

   cat <<'EOF' > "$tmpdir/policies/allow-all.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: allow-all
       rules:
         - action: allow
           when: true
   EOF
   ```

2. **Start the proxy**:

   ```bash
   go run . --log-level=info proxy serve --config "$tmpdir/proxy.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

3. **Download through the proxy** using Dockerized pip (Mac/Windows use `host.docker.internal`, Linux can add `--network host` and hit `http://127.0.0.1:8081`):

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     -e PIP_NO_CACHE_DIR=off \
     -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
     python:3.12 \
     bash -lc "pip download requests==2.31.0 --no-deps -d /work --index-url http://host.docker.internal:8081/simple --trusted-host host.docker.internal"
   ```

   Expected result: pip reports `Successfully downloaded requests` and the wheel appears under `$tmpdir/artifacts`.

4. **Overlay a deny policy** that blocks `pkginfo` and restart:

   ```bash
   cat <<'EOF' > "$tmpdir/policies/block-pkginfo.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: block-pkginfo
       rules:
         - action: deny
           when: request.package == "pkginfo"
           reason: "blocked package (pkginfo)"
           status: 403
           headers:
             X-Deputy-Policy: block-pypi
   EOF

   kill $(cat "$tmpdir/proxy.pid")
   go run . --log-level=info proxy serve \
     --config "$tmpdir/proxy.yaml" \
     --policy "$tmpdir/policies/block-pkginfo.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

5. **Attempt to download the blocked package**:

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     -e PIP_NO_CACHE_DIR=off \
     -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
     python:3.12 \
     bash -lc "pip download pkginfo==1.5.0.1 --no-deps -d /work --index-url http://host.docker.internal:8081/simple --trusted-host host.docker.internal"
   ```

   pip prints:

   ```
   ERROR: Could not find a version that satisfies the requirement pkginfo==1.5.0.1 (from versions: none)
   ERROR: No matching distribution found for pkginfo==1.5.0.1
   ```

   The proxy log simultaneously shows `request denied … reason="blocked package (pkginfo)"`. If you need to inspect the raw HTTP response, run `curl -i http://127.0.0.1:8081/simple/pkginfo/` to see `HTTP/1.1 403` plus the `X-Deputy-Policy: block-pypi` header and the textual reason.

6. **Cleanup**:

   ```bash
   kill $(cat "$tmpdir/proxy.pid")
   rm -rf "$tmpdir"
   ```

This gives Python users the same confidence-building loop before switching `pip config set global.index-url http://proxy/simple` in their real environments.

### RubyGems Proxy Hands-On Example

Rubyists can follow the same pattern with Docker’s `ruby:3.3` image and the `gem fetch` command.

1. **Workspace + config**:

   ```bash
   tmpdir=$(mktemp -d /tmp/deputy-rubygems-proxy-XXXXXX)
   mkdir -p "$tmpdir/policies" "$tmpdir/artifacts"

   cat <<EOF > "$tmpdir/proxy.yaml"
   listeners:
     - name: rubygems-proxy
       bind: ":8083"
       ecosystems: ["rubygems"]
       upstream: https://rubygems.org
       policies:
         - $tmpdir/policies/allow-all.yaml
   EOF

cat <<'EOF' > "$tmpdir/policies/allow-all.yaml"
apiVersion: policy.deputy.sh/v1alpha2
kind: PolicyBundle
policies:
  - name: allow-all
    rules:
      - action: allow
        when: true
EOF
   ```

2. **Start the proxy**:

   ```bash
   go run . --log-level=info proxy serve --config "$tmpdir/proxy.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

3. **Happy path** — fetch Bundler through the proxy from inside Docker (again, Linux hosts can prefer `--network host` and `http://127.0.0.1:8083`):

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     ruby:3.3 \
     bash -lc "gem fetch bundler -v 2.4.22 --clear-sources --source http://host.docker.internal:8083"
   ```

   `bundler-2.4.22.gem` lands in `$tmpdir/artifacts` and the proxy quietly streams it back from `https://rubygems.org`.

4. **Overlay a deny policy** for `rake` and restart:

   ```bash
   cat <<'EOF' > "$tmpdir/policies/block-rake.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: block-rake
       rules:
         - action: deny
           when: request.package == "rake"
           reason: "blocked package (rake)"
           status: 403
           headers:
             X-Deputy-Policy: block-rubygems
   EOF

   kill $(cat "$tmpdir/proxy.pid")
   go run . --log-level=info proxy serve \
     --config "$tmpdir/proxy.yaml" \
     --policy "$tmpdir/policies/block-rake.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

5. **Attempt to fetch the blocked gem**:

   ```bash
   docker run --rm \
     -v "$tmpdir/artifacts:/work" \
     -w /work \
     ruby:3.3 \
     bash -lc "gem fetch rake -v 13.2.1 --clear-sources --source http://host.docker.internal:8083"
   ```

   Output excerpt:

   ```
   ERROR:  While executing gem ... (Gem::RemoteFetcher::FetchError)
       bad response Forbidden 403 (Gem::RemoteFetcher::FetchError)
   ```

   The proxy log includes `request denied package=rake version=13.2.1` and a quick `curl -i http://127.0.0.1:8083/gems/rake-13.2.1.gem` shows `HTTP/1.1 403` plus `X-Deputy-Policy: block-rubygems`.

6. **Cleanup**:

   ```bash
   kill $(cat "$tmpdir/proxy.pid")
   rm -rf "$tmpdir"
   ```

New users can copy these commands verbatim to validate RubyGems traffic before pointing their local `gem sources` at Deputy.

### Go Module Proxy Hands-On Example

Because Go tooling relies on GOPROXY, you can validate end-to-end behavior entirely inside Docker’s `golang:1.22` image.

1. **Workspace + config**:

   ```bash
   tmpdir=$(mktemp -d /tmp/deputy-gomod-proxy-XXXXXX)
   mkdir -p "$tmpdir/policies" "$tmpdir/cache" "$tmpdir/work"

   cat <<EOF > "$tmpdir/proxy.yaml"
   listeners:
     - name: go-proxy
       bind: ":8080"
       ecosystems: ["go"]
       upstream: https://proxy.golang.org
       policies:
         - $tmpdir/policies/allow-all.yaml
   EOF

   cat <<'EOF' > "$tmpdir/policies/allow-all.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: allow-all
       rules:
         - action: allow
           when: true
   EOF
   ```

2. **Start the proxy**:

   ```bash
   go run . --log-level=info proxy serve --config "$tmpdir/proxy.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

3. **Download via GOPROXY** — the command below mounts a writable module cache, points `GOPROXY` at Deputy, and downloads `golang.org/x/text@v0.14.0`. Linux hosts can use `--network host` and `http://127.0.0.1:8080` if `host.docker.internal` is unavailable.

   ```bash
   docker run --rm \
     -v "$tmpdir/cache:/go/pkg/mod" \
     -v "$tmpdir/work:/work" \
     -w /work \
     -e GOPROXY=http://host.docker.internal:8080,direct \
     -e GO111MODULE=on \
     -e GOSUMDB=off \
     golang:1.22 \
     bash -lc 'export PATH=/usr/local/go/bin:$PATH
cat <<"EOF" > go.mod
module example.com/proxytest

go 1.22
EOF
GOMODCACHE=/go/pkg/mod go mod download golang.org/x/text@v0.14.0'
   ```

   The module populates `$tmpdir/cache`, proving the CLI can talk to the proxy.

4. **Overlay a deny policy** — block `github.com/pkg/errors` and restart:

   ```bash
   cat <<'EOF' > "$tmpdir/policies/block-errors.yaml"
   apiVersion: policy.deputy.sh/v1alpha2
   kind: PolicyBundle
   policies:
     - name: block-errors
       rules:
         - action: deny
           when: request.module == "github.com/pkg/errors"
           reason: "blocked module (errors)"
           status: 403
           headers:
             X-Deputy-Policy: block-gomod
   EOF

   kill $(cat "$tmpdir/proxy.pid")
   go run . --log-level=info proxy serve \
     --config "$tmpdir/proxy.yaml" \
     --policy "$tmpdir/policies/block-errors.yaml" \
     > "$tmpdir/proxy.log" 2>&1 &
   echo $! > "$tmpdir/proxy.pid"
   ```

5. **Attempt to download the blocked module**:

   ```bash
   docker run --rm \
     -v "$tmpdir/cache:/go/pkg/mod" \
     -v "$tmpdir/work:/work" \
     -w /work \
     -e GOPROXY=http://host.docker.internal:8080,direct \
     -e GO111MODULE=on \
     -e GOSUMDB=off \
     golang:1.22 \
     bash -lc 'export PATH=/usr/local/go/bin:$PATH
cat <<"EOF" > go.mod
module example.com/proxytest

go 1.22
EOF
GOMODCACHE=/go/pkg/mod go mod download github.com/pkg/errors@v0.9.1'
   ```

   Output excerpt:

   ```
   go: github.com/pkg/errors@v0.9.1: reading http://host.docker.internal:8080/github.com/pkg/errors/@v/v0.9.1.info: 403 Forbidden
       server response: blocked module (errors)
   ```

   `curl -i http://127.0.0.1:8080/github.com/pkg/errors/@v/v0.9.1.zip` shows the matching `X-Deputy-Policy: block-gomod` header for extra confirmation.

6. **Cleanup**:

   ```bash
   kill $(cat "$tmpdir/proxy.pid")
   rm -rf "$tmpdir"
   ```

Once this works you can safely point `GOPROXY` at Deputy in your actual Go toolchains (`GOPROXY=http://proxy:8080,direct GOSUMDB=off go build ...`).

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
3. Write YAML policies (see `POLICY.md`) and bundle them: `deputy policy bundle --out policy/corp.bundle.json policy/*.yaml`.
4. Run `deputy proxy check --config proxy.yaml`.
5. Launch the proxy: `deputy proxy serve --config proxy.yaml`.
6. Point `GOPROXY` (and later `PIP_INDEX_URL`, `npm config set registry`) at the Deputy listener.

With that, Deputy becomes both a scanner _and_ an enforcement point, using the same inventory intelligence across the SDLC.
