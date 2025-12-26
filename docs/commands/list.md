# `deputy list`

List dependencies in a repository as Package URLs (PURLs).

**Aliases:** `ls`

## Synopsis

```
deputy list [repo] [flags]
deputy ls [repo] [flags]
```

## When to Use

- Quick dependency inventory (lighter than SBOM)
- Scripting and automation
- Verifying what Deputy detects
- Grep/jq-friendly output

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--ref` | | `HEAD` | Git reference (commit, tag, branch) |
| `--format` | `-f` | `text` | Output format: `text`, `tsv`, `json` |
| `--output` | `-o` | stdout | Output file path |
| `--ecosystems` | | all | Filter by ecosystem |
| `--only-direct` | | `false` | Only show direct dependencies |
| `--show-sources` | | `false` | Show manifest/lockfile sources |
| `--no-header` | | `false` | Omit header in text/tsv formats |

## Examples

### Basic Usage

```console
# List all dependencies
$ deputy list

# List from a remote repo
$ deputy list github.com/hashicorp/vault --ref v1.16.0
```

### Filtering

```console
# Only direct dependencies
$ deputy list --only-direct

# Only Go and npm
$ deputy list --ecosystems go,npm
```

### Output Formats

```console
# JSON for scripting
$ deputy list --format json | jq '.items[] | {purl: .purl, direct: .isDirect}'

# TSV for pipelines
$ deputy list --format tsv --no-header | cut -f1

# Save to file
$ deputy list --output deps.txt
```

### Show Sources

```console
# See which files dependencies came from
$ deputy list --show-sources
```

## Output

### Text Format

```
PURL                                              DIRECT
pkg:golang/github.com/example/pkg@v1.2.3          true
pkg:golang/github.com/other/dep@v2.0.0            false
pkg:npm/lodash@4.17.21                            true
```

### TSV Format

```
purldirect
pkg:golang/github.com/example/pkg@v1.2.3true
pkg:golang/github.com/other/dep@v2.0.0false
```

### JSON Format

```json
{
  "repo": "/path/to/repo",
  "ref": "HEAD",
  "commit": "abc123d...",
  "generated": "2025-01-15T10:30:00Z",
  "count": 42,
  "items": [
    {
      "ecosystem": "go",
      "name": "github.com/example/pkg",
      "version": "v1.2.3",
      "module": "github.com/example/pkg",
      "isDirect": true,
      "purl": "pkg:golang/github.com/example/pkg@v1.2.3",
      "sources": "go.mod"
    }
  ]
}
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Errors |

## Comparison with SBOM

| Feature | `deputy list` | `deputy sbom` |
| --- | --- | --- |
| Output size | Compact | Full document |
| Metadata | Minimal | Rich (licenses, etc.) |
| Use case | Scripting, quick checks | Compliance, attestation |
| Format | PURL list | CycloneDX/SPDX |

## See Also

- [SBOM command](sbom.md)
- [Inventory concepts](../concepts/inventory-and-sboms.md)

## Code Pointers

- CLI: [`internal/cli/cmd/list.go`](../../internal/cli/cmd/list.go)
- Inventory: [`internal/inventory`](../../internal/inventory)
