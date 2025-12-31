# Deputy Setup Action

Install the Deputy CLI for software supply chain security scanning.

## Usage

```yaml
- uses: picatz/deputy/actions/setup@main
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `version` | Deputy version to install (`latest`, `v1.0.0`, commit SHA) | `latest` |
| `go-version` | Go version to use (`stable`, `1.23`). Ignored if `go-version-file` is set. | `stable` |
| `go-version-file` | Path to `go.mod` or `go.work` to extract Go version from `toolchain`/`go` directive | `''` |
| `github-token` | Token for API access | `''` |

## Outputs

| Output | Description |
|--------|-------------|
| `version` | Installed Deputy version |
| `path` | Path to Deputy binary |
| `go-version` | Go version used for installation |

## Examples

### Basic

```yaml
- uses: picatz/deputy/actions/setup@main
```

### Pin Deputy Version

```yaml
- uses: picatz/deputy/actions/setup@main
  with:
    version: v1.0.0
```

### Use Go Version from go.mod

Recommended for consistency with your project's Go toolchain:

```yaml
- uses: picatz/deputy/actions/setup@main
  with:
    go-version-file: go.mod
```

This respects the `toolchain` directive if present, falling back to the `go` directive.

### Specific Go Version

```yaml
- uses: picatz/deputy/actions/setup@main
  with:
    go-version: '1.23'
```

### With Token for Private Repos

```yaml
- uses: picatz/deputy/actions/setup@main
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Caching

This action uses `actions/setup-go@v5` which automatically caches `GOCACHE` and `GOMODCACHE` using `go.sum` as the cache key. No additional configuration is needed.

## See Also

- [Scan Action](../scan/README.md) - Vulnerability scanning
- [SBOM Action](../sbom/README.md) - SBOM generation
- [Diff Action](../diff/README.md) - Dependency diff
