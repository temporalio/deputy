# `deputy list`

List dependencies in a target as Package URLs (PURLs).

**Aliases:** `ls`

## Synopsis

```
deputy list [target] [flags]
deputy ls [target] [flags]
```

## Supported Targets

- **Local directory** (default: current directory)
- **Remote Git repository** (`https://github.com/owner/repo`)
- **Container image** (`docker://nginx:1.25` or `--source remote nginx:1.25`)
- **Specific Git ref** (`--ref v1.0.0`)

## When to Use

- Quick dependency inventory (lighter than SBOM)
- Scripting and automation
- Verifying what Deputy detects
- Grep/jq-friendly output
- Auditing container image contents

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--ref` | | `HEAD` | Git reference (commit, tag, branch) |
| `--format` | `-f` | `text` | Output format: `text`, `tsv`, `json` |
| `--output` | `-o` | stdout | Output file path |
| `--ecosystems` | | all | Filter by ecosystem |
| `--direct` | | `false` | Alias for `--only-direct` |
| `--only-direct` | | `false` | Only show direct dependencies |
| `--no-header` | | `false` | Omit header in text/tsv formats |
| `--source` | | | Target source type: `remote`, `docker-daemon`, `tarball`, `oci-archive`, `oci-layout` |
| `--platform` | | | Platform for container images (`os/arch[/variant]`) |

## Examples

### Basic Usage

```console
# List all dependencies in current directory
$ deputy list

# List from a remote repo
$ deputy list github.com/hashicorp/vault

# List at a specific Git ref
$ deputy list --ref v1.16.0
```

### Container Images

```console
# List packages in a container image
$ deputy list docker://nginx:1.25

# Using --source flag for bare image refs
$ deputy list --source remote alpine:3.19

# Local Docker daemon image
$ deputy list --source docker-daemon myapp:latest

# Specify platform for multi-arch images
$ deputy list --source remote --platform linux/amd64 nginx:latest
```

### Filtering

```console
# Only direct dependencies
$ deputy list --direct

# Only Go and npm
$ deputy list --ecosystems go,npm
```

### Output Formats

```console
# JSON for scripting
$ deputy list --format json | jq '.packages[] | {purl: .purl, direct: .direct}'

# TSV for pipelines
$ deputy list --format tsv --no-header | cut -f1

# Save to file
$ deputy list --output deps.txt
```

## Output

### Text Format

```
PURL                                              DIRECT
pkg:golang/github.com/example/pkg@v1.2.3          direct
pkg:golang/github.com/other/dep@v2.0.0            indirect
pkg:npm/lodash@4.17.21                            direct

Summary:
  3 total packages (2 direct, 1 indirect)
```

### TSV Format

```
purl	direct
pkg:golang/github.com/example/pkg@v1.2.3	true
pkg:golang/github.com/other/dep@v2.0.0	false
```

### JSON Format

```json
{
  "target": {
    "kind": "TARGET_KIND_GIT",
    "display_path": "/path/to/repo",
    "local_path": "/path/to/repo",
    "ref": "HEAD",
    "effective_ref": "HEAD~0",
    "commit_hash": "abc123d..."
  },
  "packages": [
    {
      "name": "github.com/example/pkg",
      "version": "v1.2.3",
      "ecosystem": "Go",
      "purl": "pkg:golang/github.com/example/pkg@v1.2.3",
      "direct": true,
      "locations": ["go.mod"]
    }
  ],
  "stats": {
    "total_packages": 42,
    "direct_packages": 12,
    "transitive_packages": 30,
    "ecosystems": {
      "Go": 42
    }
  }
}
```

`packages` contains the returned packages after request filters. With
`--direct` or `--only-direct`, `packages` contains only direct dependencies.
`stats` summarizes the full discovered inventory after ecosystem and
exclude-path filters, before direct-only filtering, so `stats.total_packages`
can be larger than the length of `packages`. Packages are sorted by PURL, then
directness, name, version, and ecosystem for stable CLI, JSON, API, and MCP
output.

### Container Image Output

Container images show system packages (no direct/indirect distinction):

```
PURL                                                                            DIRECT
pkg:apk/alpine/alpine-baselayout-data@3.4.3-r2?arch=x86_64&distro=3.19.9       indirect
pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=3.19.9                    indirect
pkg:apk/alpine/musl@1.2.4_git20230717-r5?arch=x86_64&distro=3.19.9             indirect

Summary:
  15 total packages (0 direct, 15 indirect)
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
| Container support | Yes | Yes |

## Performance

`deputy list` is optimized for speed:

- **Repository scan**: ~0.1-0.5s (no vulnerability lookup)
- **Container image**: Varies by image size (network-bound for remote images)
- **Git ref checkout**: ~0.2s additional

Unlike `deputy scan`, `list` does not query the OSV vulnerability database, making it significantly faster for inventory-only operations.

## See Also

- [SBOM command](sbom.md)
- [Scan command](scan.md): vulnerability scanning with container support
- [Inventory concepts](../concepts/inventory-and-sboms.md)

## Code Pointers

- CLI: [`internal/cli/cmd/list.go`](../../internal/cli/cmd/list.go)
- Inventory: [`internal/inventory`](../../internal/inventory)
- Container extraction: [`internal/server/list_handler.go`](../../internal/server/list_handler.go)
