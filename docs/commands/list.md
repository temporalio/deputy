# `deputy list`

List dependencies in a target as Package URLs (PURLs), or enumerate available resources in a cloud collection.

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
- **Container registry collections** (`docker://gcr.io/project/repo/` - trailing slash lists tags)
- **GitHub organization collections** (`github://kubernetes/` - trailing slash lists repos)
- **Specific Git ref** (`--ref v1.0.0`)
- **AWS resources** (`aws://ami/ami-xxx`, `aws://ebs/snap-xxx`)
- **AWS collections** (`aws://amis`, `aws://ebs-snapshots`)

## When to Use

- Quick dependency inventory (lighter than SBOM)
- Scripting and automation
- Verifying what Deputy detects
- Grep/jq-friendly output
- Auditing container image contents
- Discovering AWS AMIs/snapshots for batch scanning
- Building CI/CD pipelines that audit cloud resources

## Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--ref` | | `HEAD` | Git reference (commit, tag, branch) |
| `--format` | `-f` | `text` | Output format: `text`, `tsv`, `json` |
| `--output` | `-o` | stdout | Output file path |
| `--ecosystems` | | all | Filter by ecosystem |
| `--only-direct` | | `false` | Only show direct dependencies |
| `--no-header` | | `false` | Omit header in text/tsv formats |
| `--source` | | | Target source type: `remote`, `docker-daemon`, `tarball`, `oci-archive`, `oci-layout` |
| `--platform` | | | Platform for container images (`os/arch[/variant]`) |
| `--page-size` | | `100` | Number of results per page (max 1000) |
| `--page-token` | | | Continuation token from previous page |
| `--filter` | | | CEL expression to filter discovered targets |

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

### Container Registry Collections

List tags in a container repository by adding a trailing slash:

```console
# List all tags in a GCR repository
$ deputy list docker://gcr.io/myproject/myapp/

# List tags in GHCR
$ deputy list docker://ghcr.io/myorg/myimage/

# List tags in Docker Hub
$ deputy list docker://library/alpine/

# List tags in ECR (uses AWS credentials)
$ deputy list docker://123456789012.dkr.ecr.us-west-2.amazonaws.com/myrepo/

# Pagination support
$ deputy list docker://library/nginx/ --page-size 50

# Filter with CEL expressions
$ deputy list docker://library/alpine/ --filter 'name.startsWith("3.")'

# JSON output for scripting
$ deputy list docker://gcr.io/myproject/myapp/ -f json | jq -r '.discovered_targets[].uri'
```

**Note:** The trailing slash indicates a collection (list tags). Without the trailing slash, Deputy treats it as a specific image to scan for packages.

**Authentication:** Uses Docker credential helpers, `~/.docker/config.json`, or environment-specific tokens (ECR uses AWS credentials, GHCR uses `GITHUB_TOKEN`).

### GitHub Organization Collections

List repositories in a GitHub organization or user namespace:

```console
# List repos in an organization
$ deputy list github://kubernetes/

# List repos for a user
$ deputy list github://torvalds/

# Alternative URL formats
$ deputy list github.com/hashicorp/
$ deputy list https://github.com/docker/

# Pagination
$ deputy list github://anthropics/ --page-size 10

# Filter with CEL expressions
$ deputy list github://golang/ --filter 'name.contains("tools")'
$ deputy list github://hashicorp/ --filter 'metadata["stars"] > "100"'

# JSON output with metadata (stars, language, topics)
$ deputy list github://golang/ -f json | jq '.discovered_targets[] | {name, stars: .metadata.stars}'
```

**Authentication:** Set `GITHUB_TOKEN` environment variable for higher rate limits and access to private repositories.

### AWS Cloud Resources

When the target is a **collection URI** (plural resource name), Deputy lists available resources rather than packages:

```console
# List your AMIs
$ deputy list aws://amis?owner=self

# List AMIs in a specific region
$ deputy list aws://amis?region=us-west-2

# List AMIs with tag filters
$ deputy list aws://amis?owner=self&tags.env=prod

# List EBS snapshots
$ deputy list aws://ebs-snapshots

# List snapshots with tag filter
$ deputy list aws://snapshots?tags.backup=daily
```

When the target is a **specific resource URI** (singular with ID), Deputy lists packages inside:

```console
# List packages in a specific AMI
$ deputy list aws://ami/ami-0123456789abcdef0

# With region override
$ deputy list aws://ami/ami-0123456789abcdef0?region=us-east-1

# List packages in an EBS snapshot
$ deputy list aws://ebs/snap-0123456789abcdef0

# Bare resource IDs also work
$ deputy list ami-0123456789abcdef0
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

### Pipeline: Discover and Scan

Combine collection listing with scanning to audit multiple resources:

```console
# List and scan all tags in a container repository
$ deputy list docker://gcr.io/myproject/myapp/ -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -P4 -I{} deputy scan {}

# Scan latest 5 alpine versions
$ deputy list docker://library/alpine/ --page-size 5 --filter 'name.startsWith("3.2")' -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -I{} deputy scan {} --format json

# List and scan all repos in a GitHub org
$ deputy list github://myorg/ -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -P4 -I{} deputy scan {}

# List AMIs and scan each one
$ deputy list aws://amis?owner=self -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -I{} deputy scan {}

# Scan all prod AMIs
$ deputy list aws://amis?owner=self&tags.env=prod -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -P4 -I{} deputy scan {} --format json
```

## Output

### Collection Output (Text Format)

When listing a collection, output shows discovered targets:

```
TARGET                                          NAME                    CREATED
aws://ami/ami-0123456789abcdef0                 my-app-v1.2.3          2024-01-15
aws://ami/ami-0abcdef1234567890                 my-app-v1.2.2          2024-01-10
aws://ami/ami-9876543210fedcba0                 base-image-v1.0.0      2023-12-01

Total: 3 targets
```

### Package Output (Text Format)

When listing packages in a target:

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

### Collection JSON Format

When listing a collection:

```json
{
  "is_collection": true,
  "discovered_targets": [
    {
      "uri": "docker://index.docker.io/library/alpine:3.19",
      "name": "3.19",
      "created_at": "2024-01-15T10:30:00Z",
      "metadata": {
        "repository": "index.docker.io/library/alpine",
        "tag": "3.19",
        "digest": "sha256:abc123..."
      }
    }
  ],
  "next_page_token": "3.19",
  "stats": {
    "total_packages": 5
  }
}
```

### Package JSON Format

When listing packages in a target:

```json
{
  "target": "/path/to/repo",
  "ref": "HEAD",
  "commit": "abc123d...",
  "generated": "2025-01-15T10:30:00Z",
  "count": 42,
  "items": [
    {
      "ecosystem": "go",
      "name": "github.com/example/pkg",
      "version": "v1.2.3",
      "isDirect": true,
      "purl": "pkg:golang/github.com/example/pkg@v1.2.3",
      "sources": "go.mod"
    }
  ]
}
```

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

## Collection URI Reference

### Container Registry Collections

| URI Pattern | Description |
| --- | --- |
| `docker://gcr.io/project/repo/` | List tags in GCR repository |
| `docker://ghcr.io/owner/repo/` | List tags in GHCR repository |
| `docker://library/nginx/` | List tags in Docker Hub library image |
| `docker://myorg/myapp/` | List tags in Docker Hub org repo |
| `docker://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo/` | List tags in ECR |
| `oci://registry.example.com/ns/repo/` | List tags (OCI scheme) |

**Note:** The trailing slash is required to indicate a collection. Without it, the target is treated as a specific image.

### GitHub Organization Collections

| URI Pattern | Description |
| --- | --- |
| `github://kubernetes/` | List repos in kubernetes org |
| `github://torvalds/` | List repos for torvalds user |
| `github.com/hashicorp/` | Alternative format (github.com prefix) |
| `https://github.com/docker/` | Full URL format |

**Metadata available in JSON output:** `owner`, `full_name`, `default_branch`, `visibility`, `language`, `archived`, `fork`, `stars`, `html_url`, `topics`

### AWS Collections

| URI Pattern | Description |
| --- | --- |
| `aws://amis` | List all visible AMIs |
| `aws://amis?owner=self` | List AMIs owned by current account |
| `aws://amis?owner=amazon` | List Amazon-provided AMIs |
| `aws://amis?region=us-west-2` | List AMIs in specific region |
| `aws://amis?tags.env=prod` | Filter by tag |
| `aws://ebs-snapshots` | List EBS snapshots |
| `aws://snapshots` | Alias for ebs-snapshots |
| `aws://lambdas` | List Lambda functions |
| `aws://functions` | Alias for lambdas |
| `aws://ecr-images` | List ECR images |

Query parameters can be combined: `aws://amis?owner=self&region=us-east-1&tags.team=platform`

## See Also

- [SBOM command](sbom.md)
- [Scan command](scan.md) — vulnerability scanning with container support
- [Inventory concepts](../concepts/inventory-and-sboms.md)

## Code Pointers

- CLI: [`internal/cli/cmd/list.go`](../../internal/cli/cmd/list.go)
- Inventory: [`internal/inventory`](../../internal/inventory)
- Container extraction: [`internal/server/list_handler.go`](../../internal/server/list_handler.go)
