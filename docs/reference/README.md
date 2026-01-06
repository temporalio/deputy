# Reference

Stable, "look it up" documentation for Deputy configuration.

## Quick Links

- [Capabilities](capabilities.md) — Feature matrix: ecosystems, commands, outputs
- [Configuration file](configuration.md) — YAML config file format and precedence
- [Logging](logging.md) — Log levels and output formats
- [Policy framework](policy-framework.md) — Policy bundles, entrypoints, and evaluation context
- [Policy inputs](policy-inputs.md) — Entrypoints, variables, and payload shapes
- [Policy spec](policy-spec.md) — Formal schema and validation rules
- [Proxy design](proxy.md) — Proxy architecture and policy enforcement flow
- [Environment variables](#environment-variables) — All `DEPUTY_*` variables

## Environment Variables

### Logging

| Variable | Values | Default | Description |
| --- | --- | --- | --- |
| `DEPUTY_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` | Log verbosity |
| `DEPUTY_LOG_FORMAT` | `text`, `json` | `text` | Output format |
| `DEPUTY_LOG_COLOR` | `true`, `false` | auto | ANSI colors in text format |
| `DEPUTY_LOG_SOURCE` | `true`, `false` | `false` | Include source file/line |

### Configuration

| Variable | Description |
| --- | --- |
| `DEPUTY_CONFIG` | Path to config file (overrides default search) |

### Scanning

| Variable | Description |
| --- | --- |
| `DEPUTY_SCAN_ECOSYSTEMS` | Comma-separated ecosystems to scan (e.g., `go,npm`) |
| `DEPUTY_SCAN_SKIP_CACHE` | Disable result caching (`true`/`false`) |

### Policy

| Variable | Description |
| --- | --- |
| `DEPUTY_POLICY_PATHS` | Comma-separated paths to policy files/directories |
| `DEPUTY_POLICY_MODE` | Default mode: `enforce` or `advisory` |

### Proxy

| Variable | Description |
| --- | --- |
| `DEPUTY_PROXY_ADDR` | Address to bind proxy server (default: `:8080`) |
| `DEPUTY_PROXY_POLICIES` | Comma-separated policy file paths |

### External Services

| Variable | Description |
| --- | --- |
| `GITHUB_TOKEN` | GitHub PAT for improved rate limits during enrichment |
| `CODEX_API_KEY` | API key for Codex agent integration |
| `ANTHROPIC_API_KEY` | API key for Anthropic agent integration |

## Configuration Precedence

```
CLI flags > Environment variables > Config file > Built-in defaults
```

See the [configuration reference](configuration.md) for details.
