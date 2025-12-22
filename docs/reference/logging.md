# Logging

Deputy uses structured logging via Go's `log/slog` package. Logs go to stderr, keeping stdout clean for command output.

## Quick Reference

| Control | Flag | Environment Variable | Values |
|---------|------|---------------------|--------|
| Level | `--log-level` | `DEPUTY_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| Format | `--log-format` | `DEPUTY_LOG_FORMAT` | `text`, `json` |
| Color | - | `DEPUTY_LOG_COLOR` | `true`, `false` |
| Source | - | `DEPUTY_LOG_SOURCE` | `true`, `false` |

## Log Levels

| Level | When to Use |
|-------|-------------|
| `debug` | Troubleshooting, development, verbose tracing |
| `info` | Normal operation, key events (default) |
| `warn` | Recoverable issues, degraded operation |
| `error` | Failures requiring attention |

### Example: Debug output

```console
$ deputy scan --log-level debug

time=2024-12-15T10:30:00.000Z level=DEBUG msg="loading config" path=.deputy.yaml
time=2024-12-15T10:30:00.001Z level=DEBUG msg="resolving target" target=. ref=HEAD
time=2024-12-15T10:30:00.050Z level=DEBUG msg="detected manifest" file=go.mod ecosystem=go
time=2024-12-15T10:30:00.100Z level=DEBUG msg="inventory complete" packages=47 direct=12 indirect=35
time=2024-12-15T10:30:00.150Z level=DEBUG msg="querying OSV" ecosystem=Go packages=47
time=2024-12-15T10:30:01.200Z level=INFO msg="scan complete" vulnerabilities=3 duration=1.2s
```

## Output Formats

### Text format (default)

Human-readable, colorized when connected to a terminal:

```console
$ deputy scan --log-level info

time=2024-12-15T10:30:00.000Z level=INFO msg="scanning" target=. ref=HEAD
time=2024-12-15T10:30:01.200Z level=INFO msg="scan complete" vulnerabilities=3
```

### JSON format

Machine-readable, ideal for log aggregation (Datadog, Splunk, CloudWatch):

```console
$ deputy scan --log-level info --log-format json

{"time":"2024-12-15T10:30:00.000Z","level":"INFO","msg":"scanning","target":".","ref":"HEAD"}
{"time":"2024-12-15T10:30:01.200Z","level":"INFO","msg":"scan complete","vulnerabilities":3}
```

## Configuration

### Via flags

```bash
deputy scan --log-level debug --log-format json
```

### Via environment

```bash
export DEPUTY_LOG_LEVEL=debug
export DEPUTY_LOG_FORMAT=json
deputy scan
```

### Via config file

```yaml
# .deputy.yaml
logging:
  level: info
  format: text
  color: true
  source: false
```

## Common Patterns

### Debugging network issues

```bash
# See OSV API calls and timing
DEPUTY_LOG_LEVEL=debug deputy scan 2>&1 | grep -i osv

# Example output:
# time=... level=DEBUG msg="querying OSV" ecosystem=Go packages=47
# time=... level=DEBUG msg="OSV response" status=200 duration=1.05s
```

### CI/CD pipeline logging

```bash
# JSON for log aggregation, info level
deputy scan --log-format json --log-level info 2> scan.log

# Or capture both stdout and stderr
deputy scan --format json > results.json 2> debug.log
```

### Troubleshooting policy evaluation

```bash
# See policy decisions in detail
deputy scan --policy rules.yaml --log-level debug 2>&1 | grep -i policy

# Example output:
# time=... level=DEBUG msg="loading policy" path=rules.yaml
# time=... level=DEBUG msg="evaluating rule" policy=block-critical action=deny
# time=... level=DEBUG msg="policy result" action=deny reason="critical vuln found"
```

### Quiet mode

```bash
# Suppress all but errors
deputy scan --log-level error

# Or redirect stderr to /dev/null
deputy scan 2>/dev/null
```

## Log Fields

Common structured fields in log entries:

| Field | Description |
|-------|-------------|
| `time` | RFC3339 timestamp |
| `level` | Log level (DEBUG, INFO, WARN, ERROR) |
| `msg` | Human-readable message |
| `target` | Target being processed |
| `ref` | Git reference |
| `ecosystem` | Package ecosystem (go, npm, etc.) |
| `duration` | Operation timing |
| `error` | Error details (when applicable) |
| `packages` | Package count |
| `vulnerabilities` | Vulnerability count |

## Separating Logs from Output

Deputy writes:
- **Command output** (scan results, SBOMs, etc.) to **stdout**
- **Logs** (debug info, warnings, errors) to **stderr**

This allows clean piping:

```bash
# Pipe JSON output while seeing logs
deputy scan --format json 2> /tmp/debug.log | jq '.vulnerabilities'

# Capture output, ignore logs
deputy sbom --format cyclonedx-json > sbom.json 2>/dev/null

# Capture logs, ignore output
deputy scan > /dev/null 2> debug.log
```

## Performance Considerations

- `debug` level generates significant output and may slow operations
- For production CI, use `info` or `warn`
- JSON format has minimal overhead vs text

## Proxy-Specific Logging

The proxy server includes additional log fields:

```json
{
  "time": "2024-12-15T10:30:00.000Z",
  "level": "INFO",
  "msg": "request handled",
  "listener": "go-corp",
  "ecosystem": "go",
  "module": "github.com/example/pkg",
  "version": "v1.2.3",
  "action": "allow",
  "duration_ms": 45,
  "cache_hit": true
}
```

Enable with:

```bash
deputy proxy serve --config proxy.yaml --log-level info --log-format json
```

## See Also

- [Configuration](configuration.md) - Full config file reference
- [Troubleshooting](../guides/troubleshooting.md) - Common issues and solutions
