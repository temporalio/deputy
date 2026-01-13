# `deputy proxy`

Run a policy-enforcing artifact proxy for package managers.

## Synopsis

```
deputy proxy <subcommand> [flags]
deputy proxy <ecosystem> -- <command> [args...]
```

## Overview

The proxy intercepts requests to upstream registries and evaluates CEL policies against requested packages. If a policy denies a package (vulnerabilities, license issues, naming violations), the proxy blocks the download.

**Use cases:**
- Prevent vulnerable dependencies from entering codebases
- Enforce license compliance at download time
- Allowlist/denylist specific packages or versions
- Audit all package downloads

## Subcommands

| Subcommand | Description |
| --- | --- |
| [`serve`](#serve) | Run standalone proxy server |
| [`template`](#template) | Generate starter configuration |
| [`oci-config`](#oci-config) | Emit container runtime config snippets |
| [`go`](#ecosystem-wrappers) | Wrap Go commands |
| [`npm`](#ecosystem-wrappers) | Wrap npm/yarn/pnpm commands |
| [`pypi`](#ecosystem-wrappers) | Wrap pip commands |
| [`rubygems`](#ecosystem-wrappers) | Wrap gem/bundle commands |
| [`oci`](#ecosystem-wrappers) | Wrap container image pulls |

## Supported Ecosystems

| Ecosystem | Upstream | Protocol |
| --- | --- | --- |
| Go | `proxy.golang.org` | Go module proxy |
| npm | `registry.npmjs.org` | npm registry |
| PyPI | `pypi.org` | Simple API |
| RubyGems | `rubygems.org` | Gem server API |
| OCI | `registry-1.docker.io` | OCI Registry API (container images) |

---

## `serve`

Run a standalone proxy server with full configuration.

```
deputy proxy serve --config proxy.yaml
```

### Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--config` | `-c` | *required* | Path to proxy config (YAML/JSON) |
| `--policy` | | | Additional CEL policy files (repeatable) |
| `--readyz` | | `false` | Expose `/readyz` health endpoint |
| `--pprof` | | `false` | Expose `/debug/pprof/*` endpoints |
| `--vars` | | `false` | Expose `/debug/vars` (cache stats, auth metrics) |

### Example

```console
# Generate config
$ deputy proxy template > proxy.yaml

# Edit proxy.yaml to add policies...

# Run server
$ deputy proxy serve --config proxy.yaml --readyz
```

### Configuration File

```yaml
# proxy.yaml
listeners:
  - name: go-proxy
    bind: ":8080"
    ecosystems: ["go"]
    upstream: "https://proxy.golang.org"
    policies:
      - ./policies/security.yaml
      - ./policies/compliance.yaml
    max_concurrent_requests: 100

  - name: npm-proxy
    bind: ":8081"
    ecosystems: ["npm"]
    upstream: "https://registry.npmjs.org"
    policies:
      - ./policies/security.yaml
```

### Authentication (JWT/OIDC)

The proxy supports JWT-based authentication via OIDC/JWKS. When enabled, JWT claims are extracted and made available to CEL policies via the `jwt` variable.

#### Auth Modes

| Mode | Behavior |
| --- | --- |
| `disabled` | No authentication (default) |
| `optional` | Validate tokens if present, allow anonymous |
| `required` | Reject requests without valid tokens (401) |

#### Configuration Example

```yaml
listeners:
  - name: go-secure
    bind: ":8080"
    ecosystems: ["go"]
    upstream: "https://proxy.golang.org"
    policies:
      - ./policies/jwt-policies.yaml
    auth:
      mode: required
      jwks:
        url: "https://auth.example.com/.well-known/jwks.json"
        oidc_discovery: false  # Auto-discover from issuer
        refresh_interval: 1h
      # Alternative: static keys for offline validation
      # static_keys:
      #   - kid: "key-1"
      #     alg: "RS256"
      #     public_key: |
      #       -----BEGIN PUBLIC KEY-----
      #       MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
      #       -----END PUBLIC KEY-----
      issuers:
        - "https://auth.example.com"
      audiences:
        - "deputy-proxy"
      required_claims:
        - "sub"
        - "email"
      clock_skew: 30s
```

#### Auth Config Options

| Field | Type | Description |
| --- | --- | --- |
| `mode` | string | `disabled`, `optional`, or `required` |
| `jwks.url` | string | JWKS endpoint URL |
| `jwks.oidc_discovery` | bool | Auto-discover JWKS from issuer's `.well-known/openid-configuration` |
| `jwks.refresh_interval` | duration | Key refresh interval (default: 1h, min: 5m) |
| `static_keys` | list | Inline public keys (alternative to JWKS) |
| `static_keys[].kid` | string | Key ID |
| `static_keys[].alg` | string | Algorithm (RS256, ES256, EdDSA) |
| `static_keys[].public_key` | string | PEM-encoded public key |
| `issuers` | list | Allowed token issuers (iss claim) |
| `audiences` | list | Expected audiences (aud claim) |
| `required_claims` | list | Claims that must be present |
| `clock_skew` | duration | Clock drift tolerance for exp/nbf (default: 0, max: 5m) |
| `allowed_algorithms` | list | Restrict signing algorithms (default: RS256, ES256, EdDSA, PS256, etc.) |
| `max_token_size` | int | Maximum JWT token size in bytes (default: 16KB) |

#### Security Notes

- **Asymmetric algorithms only**: Symmetric algorithms (HS256, HS384, HS512) are intentionally not supported. They require shared secrets between issuers and validators, which is insecure for distributed systems.
- **TLS required**: Always use HTTPS in production to protect tokens in transit.
- **Key rotation**: Use JWKS with background refresh (`jwks.refresh_interval`) for automatic key rotation support.
- **Clock skew**: Keep `clock_skew` minimal (default: 0). Maximum allowed is 5 minutes.

#### Error Responses

| HTTP Status | Error Code | Description |
| --- | --- | --- |
| 401 | `missing_token` | No Authorization header (mode=required) |
| 401 | `invalid_token` | Malformed JWT |
| 401 | `expired_token` | Token past expiration |
| 401 | `signature_invalid` | Signature verification failed |
| 401 | `key_not_found` | No matching key in JWKS |
| 403 | `invalid_issuer` | Issuer not in allowed list |
| 403 | `invalid_audience` | Audience not in allowed list |
| 403 | `missing_claim` | Required claim not present |

#### Response Headers

Authentication failures include these headers for programmatic handling:

| Header | Description |
| --- | --- |
| `WWW-Authenticate` | `Bearer realm="deputy-proxy"` (on 401 responses) |
| `X-Deputy-Auth-Error` | Error code from table above |
| `X-Deputy-Auth-Message` | Human-readable error description |

---

## `template`

Generate a starter configuration file.

```
deputy proxy template [ecosystem]
```

### Examples

```console
# Full multi-ecosystem config
$ deputy proxy template > proxy.yaml

# Single ecosystem
$ deputy proxy template go > go-proxy.yaml
$ deputy proxy template oci > oci-proxy.yaml
```

---

## `oci-config`

Emit Docker/Podman registry config snippets for the OCI proxy.

```
deputy proxy oci-config --host 127.0.0.1:8084
deputy proxy oci-config --url https://proxy.internal:8443 --upstream ghcr.io
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--host` | | Proxy host:port (e.g., `127.0.0.1:8084`) |
| `--url` | | Proxy URL (e.g., `https://proxy.internal:8443`) |
| `--upstream` | | Upstream registry host for mirror snippets (e.g., `ghcr.io`) |

Use the emitted snippets to update Docker `daemon.json` or Podman `registries.conf`. They are templates; adapt to your deployment, TLS termination, and multiple-registry setups.

---

## Ecosystem Wrappers

Run package manager commands with policy enforcement — no server setup needed.

OCI image pulls are supported via `deputy proxy serve` and `deputy proxy oci`. The wrapper rewrites image references to the local proxy host (for example, `ubuntu:latest` becomes `127.0.0.1:PORT/library/ubuntu:latest`) so container CLIs can pull through Deputy. To target non‑DockerHub registries (GHCR, ECR, Quay, Artifactory, etc.), set `--upstream` to that registry host so rewrite rules stay registry‑aware.

If you pull from multiple registries, run the wrapper once per registry (set `--upstream` each time), or run multiple listeners in `proxy.yaml` and point your runtime at the appropriate host. Deputy only rewrites image references that match the configured upstream host to avoid cross‑registry confusion.

### `deputy proxy go`

```
deputy proxy go [flags] -- <go command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream` | `https://proxy.golang.org` | Upstream Go module proxy |
| `--policy` | | Additional CEL policy files (repeatable) |

```console
# Download a module
$ deputy proxy go -- go get github.com/example/pkg@latest

# Tidy with policy enforcement
$ deputy proxy go -- go mod tidy

# With custom policy
$ deputy proxy go --policy corp.yaml -- go mod download
```

### `deputy proxy npm`

```
deputy proxy npm [flags] -- <npm/yarn/pnpm command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream` | `https://registry.npmjs.org` | Upstream npm registry |
| `--policy` | | Additional CEL policy files (repeatable) |

```console
# Install packages
$ deputy proxy npm -- npm install

# Yarn
$ deputy proxy npm -- yarn add lodash

# pnpm
$ deputy proxy npm -- pnpm install
```

### `deputy proxy pypi`

```
deputy proxy pypi [flags] -- <pip command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream` | `https://pypi.org` | Upstream PyPI index |
| `--policy` | | Additional CEL policy files (repeatable) |

```console
# Install packages
$ deputy proxy pypi -- pip install requests

# Download without installing
$ deputy proxy pypi -- pip download flask --no-deps
```

### `deputy proxy rubygems`

```
deputy proxy rubygems [flags] -- <gem/bundle command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream` | `https://rubygems.org` | Upstream RubyGems |
| `--policy` | | Additional CEL policy files (repeatable) |

```console
# Install a gem
$ deputy proxy rubygems -- gem install bundler

# Bundle install
$ deputy proxy rubygems -- bundle install
```

### `deputy proxy oci`

```
deputy proxy oci [flags] -- <container command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream` | `https://registry-1.docker.io` | Upstream OCI registry |
| `--policy` | | Additional CEL policy files (repeatable) |

```console
# Pull from Docker Hub through Deputy
$ deputy proxy oci -- docker pull ubuntu:latest

# Pull from GHCR (override upstream)
$ deputy proxy oci --upstream https://ghcr.io -- docker pull ghcr.io/acme/app:1.0
```

Docker Engine requires HTTPS or an insecure registry configuration for local HTTP registries. If pulls fail with TLS errors, add the proxy host (for example, `127.0.0.1:PORT`) to your daemon's `insecure-registries` list or run Deputy behind a TLS terminator.

For private registries, make sure your container runtime is configured to send credentials to the proxy host. Deputy forwards upstream auth headers, but some registries issue tokens scoped to the registry host; in those cases, a registry mirror configuration can be more reliable than inline rewriting.

---

## Policy Enforcement

When a policy denies a package, the proxy:

1. Returns an error to the package manager
2. Displays a detailed message explaining why
3. Suggests remediation if available

### Example Output

```
deputy proxy go -- go get github.com/vulnerable/pkg@v1.0.0

✗ github.com/vulnerable/pkg@v1.0.0

  DENIED by security.yaml:
    Critical vulnerability CVE-2024-1234 in github.com/vulnerable/pkg@v1.0.0
    
  Remediation:
    Upgrade to v1.2.0 or later
```

### Policy Variables

In proxy policies, the following variables are available:

#### `request` object

```cel
request.ecosystem    // "go", "npm", "pypi", "rubygems", "oci"
request.package      // Package name
request.version      // Requested version
request.module       // (Go) Module path
request.scope        // (npm) @org scope
request.registry     // (OCI) Registry host
request.repository   // (OCI) Repository path
request.reference    // (OCI) Tag or digest
request.tag          // (OCI) Tag, if present
request.digest       // (OCI) Digest, if present
```

#### `image` object (OCI only)

```cel
image.registry       // Registry host
image.repository     // Repository path
image.reference      // Tag or digest
image.tag            // Tag (if present)
image.digest         // Digest (if present)
image.image          // Canonical image name (registry/repository)
```

#### `target` object

```cel
target.kind          // "container-image" for OCI pulls
target.display       // "oci://<registry>/<repo>@<digest>"
target.provenance    // Normalized metadata map (registry, repository, digest, etc.)
```

#### `jwt` object (when authentication is enabled)

```cel
jwt.sub              // Subject (user/service ID)
jwt.iss              // Issuer URL
jwt.aud              // Audience(s)
jwt.exp              // Expiration timestamp (Unix seconds)
jwt.iat              // Issued-at timestamp (Unix seconds)
jwt.nbf              // Not-before timestamp (Unix seconds)
jwt.jti              // JWT ID (unique identifier)
jwt.anonymous        // true if no token provided (mode=optional)
jwt.<custom>         // Any custom claims from the token
```

#### JWT Policy Examples

Using CEL optionals (`?.field` and `.orValue()`) for cleaner null-safe access:

```yaml
# Require admin role for internal packages
# Uses optionals: jwt.?roles returns optional, orValue([]) provides default
- action: deny
  when: |
    request.package.startsWith("internal/") &&
    !jwt.?roles.orValue([]).exists(r, r == "admin")
  reason: "Internal packages require admin role"

# Block anonymous downloads of critical packages
- action: deny
  when: |
    jwt.anonymous &&
    request.package in ["aws-sdk", "stripe"]
  reason: "Authentication required for this package"

# Warn about old tokens
# Uses optionals for safe access to optional claims
- action: warn
  when: |
    !jwt.anonymous &&
    age(jwt.?iat.orValue(0)) > duration("24h")
  reason: "Token is older than 24 hours - consider refreshing"
```

See the [policy spec](../reference/policy-spec.md) for full proxy policy variables. JWT policy examples:
- [jwt-role-based-access.yaml](../../policy/examples/jwt-role-based-access.yaml) - Team/role-based package access
- [jwt-service-account.yaml](../../policy/examples/jwt-service-account.yaml) - CI/CD service account policies
- [jwt-anonymous-guard.yaml](../../policy/examples/jwt-anonymous-guard.yaml) - Require auth for sensitive packages
- [jwt-audit-logging.yaml](../../policy/examples/jwt-audit-logging.yaml) - Token age warnings

---

## Deployment Patterns

### Developer Workstation

```console
# Add to shell profile
alias goproxy='deputy proxy go --policy ~/.deputy/policy.yaml --'

# Usage
goproxy go get github.com/example/pkg
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Install with policy
  run: |
    deputy proxy npm -- npm ci
```

### Shared Proxy Server

```console
# On proxy server
$ deputy proxy serve --config proxy.yaml --readyz

# Configure clients
export GOPROXY=http://proxy.internal:8080
export npm_config_registry=http://proxy.internal:8080
```

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded, all packages allowed |
| `1` | Policy denied one or more packages |
| Non-zero | Underlying command failed |

## See Also

- [Proxy rollout guide](../guides/proxy-rollout.md)
- [Policy command reference](policy.md)
- [Proxy architecture](../reference/proxy.md)

## Code Pointers

- CLI: [`internal/cli/cmd/proxy.go`](../../internal/cli/cmd/proxy.go)
- Exec wrappers: [`internal/cli/cmd/proxy_exec.go`](../../internal/cli/cmd/proxy_exec.go)
- Proxy server: [`internal/proxy`](../../internal/proxy)
