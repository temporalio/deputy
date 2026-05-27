# Deputy Proxy Action

Configure package managers to use Deputy proxy for policy enforcement at download time. This provides defense-in-depth by blocking vulnerable or policy-violating packages before they're installed.

## Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `local` | Starts an ephemeral proxy within the workflow | Per-repo policies, simple setup |
| `remote` | Uses an existing Deputy proxy server | Centralized enforcement, organization-wide policies |

## Usage

### Local Proxy (Default)

Start a local proxy with policy enforcement:

```yaml
- uses: temporalio/deputy/actions/setup@main

- uses: temporalio/deputy/actions/proxy@main
  with:
    policy: policy/ci/security-gate.yaml
    ecosystems: go,npm

# Now go get and npm install are proxied
- run: go mod download
- run: npm ci
```

### Remote Proxy

Point to a centralized Deputy proxy:

```yaml
- uses: temporalio/deputy/actions/proxy@main
  with:
    mode: remote
    proxy-url: https://deputy-proxy.internal.example.com
    auth-token: ${{ secrets.DEPUTY_PROXY_TOKEN }}
    ecosystems: go,npm

- run: npm ci  # Proxied through central server
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `mode` | `local` (ephemeral) or `remote` (existing server) | `local` |
| `proxy-url` | URL of remote proxy (required if mode=remote) | `''` |
| `policy` | Policy file(s) for local proxy (comma-separated) | `''` |
| `config` | Path to proxy config file (advanced) | `''` |
| `upstream-go` | Upstream Go module proxy | `https://proxy.golang.org` |
| `upstream-npm` | Upstream npm registry | `https://registry.npmjs.org` |
| `upstream-pypi` | Upstream PyPI index | `https://pypi.org` |
| `upstream-rubygems` | Upstream RubyGems source | `https://rubygems.org` |
| `ecosystems` | Ecosystems to proxy (go,npm,pypi,rubygems) | `go,npm` |
| `auth-token` | JWT token for remote proxy auth | `''` |
| `use-oidc` | Use GitHub Actions OIDC token for authentication | `false` |
| `oidc-audience` | Audience for OIDC token (defaults to proxy-url) | `''` |
| `fail-on-policy-violation` | Fail if proxy blocks a package | `true` |
| `log-level` | Proxy log level | `warn` |

## Outputs

| Output | Description |
|--------|-------------|
| `proxy-url-go` | Proxy URL for Go (GOPROXY value) |
| `proxy-url-npm` | Proxy URL for npm/yarn/pnpm/bun |
| `proxy-url-pypi` | Proxy URL for pip/poetry |
| `proxy-url-rubygems` | Proxy URL for gem/bundler |
| `proxy-pid` | PID of local proxy (if mode=local) |

## Environment Variables Set

The action automatically configures these environment variables for transparent integration:

### Go
| Variable | Description |
|----------|-------------|
| `GOPROXY` | Module proxy URL with `,direct` fallback |

### JavaScript (npm/yarn/pnpm/bun)
| Variable | Description |
|----------|-------------|
| `NPM_CONFIG_REGISTRY` | npm registry URL |
| `YARN_REGISTRY` | Yarn Classic (v1) registry |
| `YARN_NPM_REGISTRY_SERVER` | Yarn Berry (v2+) registry |
| `BUN_CONFIG_REGISTRY` | Bun registry |

### Python (pip/poetry)
| Variable | Description |
|----------|-------------|
| `PIP_INDEX_URL` | pip index URL |
| `PIP_TRUSTED_HOST` | Trusted host for local proxy |
| `POETRY_REPOSITORIES_DEPUTY_URL` | Poetry repository URL |

### Ruby (gem/bundler)
| Variable | Description |
|----------|-------------|
| `GEM_HOST` | gem source URL |
| `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/` | Bundler mirror |

All standard package manager commands work without modification:
```bash
# All of these automatically use the Deputy proxy
go mod download
npm ci
yarn install
pnpm install
bun install
pip install -r requirements.txt
bundle install
```

## Examples

### Block Critical Vulnerabilities at Install Time

```yaml
name: Secure Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: temporalio/deputy/actions/setup@main

      # Start proxy with policy enforcement
      - uses: temporalio/deputy/actions/proxy@main
        with:
          policy: policy/ci/security-gate.yaml

      # These commands now go through the proxy
      # and will fail if they try to download vulnerable packages
      - run: go mod download
      - run: npm ci

      - run: go build ./...
      - run: npm run build
```

### Organization-Wide Proxy

```yaml
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Use organization's central proxy
      - uses: temporalio/deputy/actions/proxy@main
        with:
          mode: remote
          proxy-url: ${{ vars.DEPUTY_PROXY_URL }}
          auth-token: ${{ secrets.DEPUTY_PROXY_TOKEN }}

      # All package downloads enforced by central policies
      - run: npm ci
      - run: npm run build
```

### GitHub Actions OIDC Authentication

Use GitHub Actions OIDC tokens for identity-based access control. This eliminates the need for long-lived secrets and enables fine-grained policies based on workflow identity (repository, branch, actor, environment, etc.).

```yaml
name: Build with OIDC
on: [push]

permissions:
  contents: read
  id-token: write  # Required for OIDC token

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Authenticate using GitHub Actions OIDC token
      - uses: temporalio/deputy/actions/proxy@main
        with:
          mode: remote
          proxy-url: https://deputy-proxy.example.com
          use-oidc: true

      - run: npm ci
```

**Why OIDC?**

| Approach | Pros | Cons |
|----------|------|------|
| `auth-token` (secret) | Simple setup | Long-lived secret, rotation needed, same token for all workflows |
| `use-oidc` | No secrets, automatic rotation, identity-aware policies | Requires proxy OIDC configuration |

**OIDC Token Claims**

When `use-oidc: true`, the JWT token includes GitHub Actions identity claims that can be used in Deputy policies:

| Claim | Example | Policy Use Case |
|-------|---------|----------------|
| `repository` | `myorg/myrepo` | Restrict to specific repos |
| `repository_owner` | `myorg` | Org-level access control |
| `repository_visibility` | `private` | Block public repos from internal packages |
| `ref` | `refs/heads/main` | Branch-based policies |
| `actor` | `octocat` | User-based restrictions |
| `event_name` | `push` | Block PR builds from prod packages |
| `environment` | `production` | Environment-based access |
| `runner_environment` | `self-hosted` | Require self-hosted runners |
| `job_workflow_ref` | `org/.github/...@main` | Require approved reusable workflows |

**Ecosystem Support for OIDC**

| Ecosystem | OIDC Support | Notes |
|-----------|--------------|-------|
| npm | Full | `.npmrc` auth token sent as Bearer header |
| Go | Partial | Requires proxy to accept Basic Auth with bearer token (see below) |

For **npm**, OIDC authentication works seamlessly - the action configures `.npmrc` to send the token as a Bearer header.

For **Go**, the standard `.netrc` mechanism sends Basic Auth, not Bearer tokens. If your Deputy proxy requires Bearer authentication, you have two options:
1. Configure your proxy to accept Basic Auth with `username=bearer` and extract the password as the JWT
2. Use `ecosystems: npm` for OIDC-authenticated builds and fall back to `auth-token` for Go

**Proxy Configuration for OIDC**

Configure your Deputy proxy to validate GitHub Actions tokens:

```yaml
# deputy-proxy-config.yaml
listeners:
  - name: npm-proxy
    bind: ":8080"
    ecosystems: ["npm"]
    upstream: "https://registry.npmjs.org"
    policies: ["policy/github-actions.yaml"]
    auth:
      mode: required
      jwks:
        url: https://token.actions.githubusercontent.com/.well-known/jwks
      issuers:
        - https://token.actions.githubusercontent.com
      audiences:
        - https://deputy-proxy.example.com  # Must match proxy-url or oidc-audience
```

**Identity-Based Policies**

With OIDC, you can create policies that enforce access based on workflow identity:

```yaml
# policy/github-actions.yaml
policies:
  # Only allow requests from your organization
  - name: org-only
    rules:
      - action: deny
        when: jwt.?repository_owner.orValue("") != "myorg"
        reason: Only myorg repositories can access this proxy

  # Production packages only from main branch
  - name: prod-main-only
    rules:
      - action: deny
        when: |
          pkg.name.startsWith("@myorg/prod-") &&
          jwt.?ref.orValue("") != "refs/heads/main"
        reason: Production packages only available from main branch

  # Block PR builds from internal packages
  - name: no-pr-internal
    rules:
      - action: deny
        when: |
          pkg.name.startsWith("@internal/") &&
          jwt.?event_name.orValue("") in ["pull_request", "pull_request_target"]
        reason: Internal packages not available in PR builds
```

See [GitHub Actions OIDC Policy Examples](../../policy/examples/github-actions-oidc.yaml) for more patterns.

### Custom Upstream Registries

```yaml
- uses: temporalio/deputy/actions/proxy@main
  with:
    upstream-go: https://goproxy.mycorp.com
    upstream-npm: https://npm.mycorp.com
    policy: policy/security.yaml
```

### Go-Only Proxy

```yaml
- uses: temporalio/deputy/actions/proxy@main
  with:
    ecosystems: go
    policy: policy/go-security.yaml

- run: go mod download
```

### Combined with Scan Action

For maximum coverage, use both proxy (blocks at download) and scan (reports to GitHub Security):

```yaml
- uses: temporalio/deputy/actions/setup@main

# Block vulnerable packages at download time
- uses: temporalio/deputy/actions/proxy@main
  with:
    policy: policy/ci/security-gate.yaml

- run: npm ci

# Also scan and report to GitHub Security tab
- uses: temporalio/deputy/actions/scan@main
  with:
    policy: policy/ci/security-gate.yaml
    upload-sarif: true
```

## How It Works

### Local Mode

1. Generates a proxy configuration based on inputs
2. Starts `deputy proxy serve` in the background
3. Sets environment variables (`GOPROXY`, `NPM_CONFIG_REGISTRY`, etc.)
4. Package manager commands automatically route through the proxy
5. Proxy evaluates CEL policies on each package request
6. Blocked packages cause the package manager command to fail

### Remote Mode

1. Sets environment variables to point to the remote proxy
2. Configures authentication if token provided
3. All package downloads go through the central proxy
4. Central proxy enforces organization-wide policies

## Policy Examples

### Block Critical Vulnerabilities

```yaml
# policy/proxy-security.yaml
policies:
  - name: block-critical
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.severity == "CRITICAL")
        reason: "Package has critical vulnerability"
```

### Block Specific Packages

```yaml
policies:
  - name: blocklist
    vars:
      blocked: ["event-stream", "colors", "node-ipc"]
    rules:
      - action: deny
        when: pkg.name in blocked
        reason: "Package is on security blocklist"
```

### License Enforcement

```yaml
policies:
  - name: license-gate
    vars:
      allowed: ["MIT", "Apache-2.0", "BSD-3-Clause"]
    rules:
      - action: deny
        when: |
          pkg.licenses.size() > 0 &&
          pkg.licenses.all(l, !(l in allowed))
        reason: "Package license not approved"
```

## Troubleshooting

### Proxy Fails to Start

Check the proxy logs:

```yaml
- uses: temporalio/deputy/actions/proxy@main
  with:
    log-level: debug
```

### Package Download Blocked

The proxy will return an error message explaining why. Check the workflow logs for:
- Policy violation reason
- Which policy blocked the package
- Remediation suggestions

### Connection Issues with Remote Proxy

Ensure:
- `proxy-url` is accessible from GitHub Actions runners
- Authentication token is valid (if required)
- Firewall allows outbound connections

## See Also

- [Setup Action](../setup/README.md) - Install Deputy
- [Scan Action](../scan/README.md) - Vulnerability scanning
- [Proxy Rollout Guide](../../docs/guides/proxy-rollout.md) - Deploy proxy in your organization
- [Policy Examples](../../policy/examples/) - CEL policy patterns
