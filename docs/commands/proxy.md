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
| [`go`](#ecosystem-wrappers) | Wrap Go commands |
| [`npm`](#ecosystem-wrappers) | Wrap npm/yarn/pnpm commands |
| [`pypi`](#ecosystem-wrappers) | Wrap pip commands |
| [`rubygems`](#ecosystem-wrappers) | Wrap gem/bundle commands |

## Supported Ecosystems

| Ecosystem | Upstream | Protocol |
| --- | --- | --- |
| Go | `proxy.golang.org` | Go module proxy |
| npm | `registry.npmjs.org` | npm registry |
| PyPI | `pypi.org` | Simple API |
| RubyGems | `rubygems.org` | Gem server API |

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
| `--vars` | | `false` | Expose `/debug/vars` (cache stats) |

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
listen: ":8080"

ecosystems:
  go:
    enabled: true
    upstream: "https://proxy.golang.org"
  npm:
    enabled: true
    upstream: "https://registry.npmjs.org"

policies:
  - path: ./policies/security.yaml
  - path: ./policies/compliance.yaml

cache:
  enabled: true
  ttl: 1h
```

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
```

---

## Ecosystem Wrappers

Run package manager commands with policy enforcement — no server setup needed.

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

In proxy policies, the `request` object contains:

```cel
request.ecosystem    // "go", "npm", "pypi", "rubygems"
request.package      // Package name
request.version      // Requested version
request.module       // (Go) Module path
request.scope        // (npm) @org scope
```

See [`POLICY_SPEC.md`](../../POLICY_SPEC.md) for full proxy policy variables.

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

- Proxy rollout guide: [`docs/guides/proxy-rollout.md`](../guides/proxy-rollout.md)
- Policy development: [`policy.md`](policy.md)
- PROXY.md reference: [`PROXY.md`](../../PROXY.md)

## Code Pointers

- CLI: [`internal/cli/cmd/proxy.go`](../../internal/cli/cmd/proxy.go)
- Exec wrappers: [`internal/cli/cmd/proxy_exec.go`](../../internal/cli/cmd/proxy_exec.go)
- Proxy server: [`internal/proxy`](../../internal/proxy)
