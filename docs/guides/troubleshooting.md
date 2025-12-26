# Troubleshooting

Quick fixes for common issues. Use `--log-level debug` on any command for verbose output.

## Network & OSV Issues

### "No vulnerabilities found" (unexpected)

1. **Check network access**: Deputy queries `api.osv.dev` for vulnerability data.
2. **Verify inventory detection**: Run `deputy list` to confirm packages are being discovered.
3. **Check ecosystem coverage**: OSV coverage varies by ecosystem; some packages may not have data yet.

```console
# Debug mode shows OSV query details
$ deputy scan --log-level debug
```

### OSV timeouts or failures

- Deputy continues with warnings when OSV is unreachable (SBOM generation still works).
- For air-gapped environments, consider the proxy with a local OSV mirror (see the [proxy design](../reference/proxy.md)).

## Git & Repository Issues

### "could not resolve ref" errors

```console
# Wrong: shell expands @{...}
$ deputy diff HEAD@{yesterday} HEAD

# Right: quote time-based refs
$ deputy diff "HEAD@{yesterday}" HEAD
```

### "no dependencies found" in a valid repo

- Ensure you're in a directory with manifest files (`go.mod`, `package.json`, etc.).
- Check `--ref`: scanning a ref without manifest files yields empty results.
- Try `deputy list --show-sources` to see which files Deputy detects.

### Working tree vs committed state

```console
# Scan committed state (HEAD)
$ deputy scan

# Include uncommitted changes
$ deputy scan --ref WORKING
```

## Policy Issues

### Policy not evaluating as expected

1. **Lint first**: `deputy policy lint policy/*.yaml`
2. **Test in isolation**: `deputy policy eval --policy policy.yaml --input test.json`
3. **Check entrypoints**: Ensure the policy targets the right entrypoint (`scan_vulnerability` vs `scan_report`).
4. **Enable tracing**: Use `--policy-trace` (when available) to see evaluation steps.

### CEL expression errors

Common mistakes:
- Missing optional handling: use `pkg.?licenses.orValue([])` not `pkg.licenses`
- Wrong type comparisons: severity is a string (`"HIGH"`), not an enum
- List vs single value: `vulnerabilities` is a list; use `.exists()` or `.filter()`

## Proxy Issues

### Unexpected blocks

Start with advisory mode to observe without blocking:

```yaml
policies:
  - name: my-policy
    mode: advisory  # logs warnings, doesn't block
```

Then:
1. Check logs for the policy/reason that triggered
2. Validate with `deputy policy lint` / `deputy policy test`
3. Use `deputy proxy inspect --url <url>` to test specific requests

### Proxy not intercepting requests

Verify environment variables are set correctly:
- Go: `GOPROXY=http://localhost:8080`
- npm: `npm_config_registry=http://localhost:8081`
- PyPI: `PIP_INDEX_URL=http://localhost:8082/simple`

## Rate Limits & Authentication

### GitHub rate limits during enrichment

Set a token to increase limits:

```console
$ export GITHUB_TOKEN=ghp_...
$ deputy sbom --enrich-licenses
```

### deps.dev enrichment failures

- deps.dev has its own rate limits; batch operations may hit them.
- Use `--license-source scan` for local-only license detection.

## Performance Issues

### Slow scans on large repositories

- Use `--ecosystems go,npm` to limit scanning to specific ecosystems.
- For repeated scans, the proxy caches OSV results automatically.
- Consider generating an SBOM once and scanning that: `deputy sbom | deputy scan sbom -`

## Getting Help

If these don't resolve your issue:

1. Run with `--log-level debug` and check the output
2. Check [GitHub Issues](https://github.com/picatz/deputy/issues) for similar reports
3. Open a new issue with debug logs and reproduction steps
