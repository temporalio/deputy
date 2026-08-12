# `deputy server`

Start the Deputy API server, enabling remote clients to perform scans and other operations via gRPC/ConnectRPC.

## Synopsis

```
deputy server [flags]
```

## When to Use

- **Team deployments**: Run a centralized Deputy server for shared scanning
- **CI/CD integration**: Offload scanning to a dedicated server for faster builds
- **Enterprise features**: Enable centralized policy enforcement and audit logging
- **Caching benefits**: Share vulnerability data cache across multiple clients

## Connection Modes

Deputy supports two execution modes as of August 2026, with a third reserved:

| Mode | Description | Use Case |
|------|-------------|----------|
| **In-process** | Direct function calls (default) | CLI usage, zero overhead |
| **Remote server** | HTTP/2 (ConnectRPC) | Team deployments, enterprise features |
| **Local daemon** | Reserved, not yet implemented (the `--daemon` flag has no effect as of August 2026) | Shared caching, faster repeat scans |

The `server` command starts Deputy in remote server mode, listening for client connections.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--addr` | `127.0.0.1:8090` | Address to listen on (host:port) |
| `--read-timeout` | `30s` | Maximum duration for reading request |
| `--write-timeout` | `5m` | Maximum duration for writing response |
| `--idle-timeout` | `2m` | Maximum time to wait for next request |
| `--public` | `false` | Allow binding to non-loopback addresses (explicit opt-in) |
| `--insecure` | `false` | Allow no TLS/auth or policy load failures (dev only) |
| `--egress-allow-host` | none | Allowlisted egress hostnames (repeatable) |
| `--egress-allow-cidr` | none | Allowlisted egress CIDR ranges (repeatable) |
| `--egress-allow-ssh` | `false` | Allow SSH git targets (ssh://, git@host) |
| `--egress-allow-loopback` | `false` | Allow loopback targets in remote server mode |
| `--egress-allow-link-local` | `false` | Allow link-local targets in remote server mode |

## Examples

### Basic Usage

```console
# Start server on default port (loopback only)
$ deputy server

# Start server on custom port
$ deputy server --addr 127.0.0.1:9000

# Start server with custom timeouts (for large scans)
$ deputy server --write-timeout 10m

# Bind publicly with TLS + auth (production)
$ deputy server --public --addr 0.0.0.0:8090 \
    --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem \
    --auth-mode required --auth-jwks-url https://issuer/.well-known/jwks.json

# Allow internal registries (egress allowlist)
$ deputy server --egress-allow-host .corp.local --egress-allow-cidr 10.0.0.0/8
```

### Client Connections

Once the server is running, clients can connect:

```console
# CLI with --server flag
$ deputy --server http://localhost:8090 scan github.com/owner/repo

# Authenticated call against a server with --auth-mode required
$ deputy --server https://deputy.example.com:8090 --auth-token "$TOKEN" scan github.com/owner/repo

# Or set environment variables
$ export DEPUTY_SERVER=http://localhost:8090
$ export DEPUTY_AUTH_TOKEN="$TOKEN"
$ deputy scan github.com/owner/repo
```

Connection settings resolve with flag-first precedence: `--server` beats
`DEPUTY_SERVER` and `--auth-token` beats `DEPUTY_AUTH_TOKEN` when both are set.
If neither the flag nor the environment variable is set, Deputy runs in-process
(local mode).

### SDK Usage

```go
import "github.com/temporalio/deputy/sdk"

// Connect to a remote server
client, err := sdk.ConnectToServer(ctx, "http://localhost:8090")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Scan a repository
result, err := client.Scan(ctx, "github.com/owner/repo")
```

### HTTP/JSON API

The server exposes ConnectRPC endpoints accessible via HTTP:

```console
# Health check
$ curl http://localhost:8090/health

# Readiness check
$ curl http://localhost:8090/ready

# Perform a scan
$ curl -X POST http://localhost:8090/deputy.scan.v1.ScanService/Scan \
    -H "Content-Type: application/json" \
    -d '{"target": "github.com/owner/repo"}'
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/deputy.scan.v1.ScanService/Scan` | POST | Perform vulnerability scan |
| `/deputy.scan.v1.ScanService/StreamScan` | POST | Scan with streaming progress |
| `/deputy.list.v1.ListService/ListPackages` | POST | List packages in target |
| `/deputy.list.v1.ListService/ListEcosystems` | POST | List supported ecosystems |
| `/deputy.sbom.v1.SBOMService/Generate` | POST | Generate SBOM |
| `/deputy.sbom.v1.SBOMService/Diff` | POST | Diff two SBOMs |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |

## Security Considerations

### Default Binding and Fail-Closed Behavior

- The server binds to `127.0.0.1:8090` by default (local-only).
- Public binds require explicit `--public` and TLS + `--auth-mode required`.
- Auth/policy load failures fail closed unless `--insecure` is set.

### Remote Mode Restrictions

When connecting to a remote server, certain targets are restricted for security:

**Allowed targets:**
- Git URLs (`github.com/owner/repo`, `https://...`)
- Container registry references (`ghcr.io/owner/app:tag`)
- PURLs (`pkg:npm/lodash@4.17.21`)

**Rejected targets:**
- Local filesystem paths (`/path/to/project`, `./relative`)
- Stdin SBOM input (`-`)
- Local Docker daemon (`docker-daemon://`)
- Local archives (`tarball://`, `oci-archive://`, `oci-layout://`)
- Non-HTTPS git targets (`ssh://`, `git@host`, `git://`) unless explicitly allowed

For local filesystem analysis, use in-process mode (the default) instead.

### Egress Allowlisting

Remote servers can be restricted to approved internal registries/SCM hosts:

```console
# Allow private Git/OCI hosts and CIDRs
$ deputy server --egress-allow-host .corp.local --egress-allow-cidr 10.0.0.0/8
```

Non-HTTPS git targets are blocked by default; enable with `--egress-allow-ssh` if needed.

### Production Deployment

For production deployments, consider:

1. **TLS termination**: Use a reverse proxy (nginx, Caddy) for HTTPS
2. **Authentication**: Enable JWT/OIDC authentication (see below)
3. **Authorization**: Use CEL policies for RBAC/ABAC
4. **Rate limiting**: Protect against abuse
5. **Monitoring**: Enable OpenTelemetry for observability

```console
# Enable OpenTelemetry
$ DEPUTY_OTEL_ENABLED=true \
  OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317 \
  deputy server
```

### Authentication & Authorization

The server supports JWT/OIDC authentication and CEL-based authorization policies for multi-tenant deployments:

```yaml
# Server configuration
auth:
  mode: "required"  # "required" or "disabled"
  jwks:
    url: "https://auth.example.com/.well-known/jwks.json"
    oidc_discovery: true
  issuers: ["https://auth.example.com"]
  audiences: ["deputy-server"]
  required_claims: ["sub", "tenant"]

policies:
  - "policies/server-authz.yaml"
```

Service-level policy entrypoints enable authorization based on JWT claims:

| Entrypoint | Operations |
|------------|------------|
| `service_scan_request` | Scan, StreamScan |
| `service_list_request` | ListPackages, ListEcosystems |
| `service_sbom_request` | Generate, Diff |
| `service_diff_request` | Diff |
| `service_secrets_request` | Scan |
| `service_graph_request` | Resolve, Why |

Example authorization policy:

```yaml
# policies/server-authz.yaml
policies:
  - name: tenant-isolation
    entrypoints: ["service_scan_request"]
    rules:
      - action: deny
        when: |
          has(jwt.tenant) &&
          has(request.target) &&
          !request.target.contains(jwt.tenant)
        reason: "Cross-tenant access denied"
```

See [AGENTS.md](../../AGENTS.md#server-authentication--multi-tenancy) for comprehensive multi-tenant configuration.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Server shut down gracefully |
| `1` | Server error (binding, configuration, etc.) |

## See Also

- [Architecture](../development/architecture.md) - Client abstraction design
- [Configuration](../reference/configuration.md) - Environment variables
- [Observability guide](../guides/observability.md) - OpenTelemetry setup

## Code Pointers

- CLI: [`internal/cli/cmd/server.go`](../../internal/cli/cmd/server.go)
- Server: [`internal/server/`](../../internal/server/)
- Client: [`internal/client/`](../../internal/client/)
- SDK: [`sdk/`](../../sdk/)
