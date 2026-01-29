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
- **GitHub repository collections** (`github://owner/repo/` - lists branches + tags, or specific collections):
  - `/branches/`, `/tags/` - Git refs
  - `/releases/` - Software releases
  - `/commits/` - Commit history
  - `/contributors/`, `/collaborators/` - People
  - `/forks/` - Repository forks
  - `/pulls/`, `/issues/` - Issues and PRs
  - `/workflows/`, `/actions/runs/` - CI/CD
  - `/dependabot/`, `/code-scanning/`, `/secret-scanning/`, `/advisories/` - Security
- **GitHub packages collections** (`github://owner/packages/` - lists packages in org/user)
- **GitHub enterprise collections** (`github://enterprises/name/` - lists organizations)
- **Specific Git ref** (`--ref v1.0.0` or `github://owner/repo@ref`)
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
- **Supply chain security investigations:**
  - Audit repository contributors and collaborators
  - Track Dependabot alerts and security advisories
  - Monitor workflow runs and release provenance
  - Inventory enterprise organizations and their repos
  - Identify unsigned commits and external contributors
  - Enumerate published packages for artifact inventory

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
| `--all` | `-a` | `false` | Fetch all pages (for scripting; may be slow for large collections) |
| `--limit` | `-l` | `0` | Maximum total number of results (0 = no limit) |
| `--page-size` | | `100` | Number of results per page (max 1000) |
| `--page-token` | | | Continuation token from previous page |
| `--filter` | | | CEL expression to filter discovered targets |
| `--quick` | | `false` | Skip metadata fetching for faster listing (no digest/created_at) |

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

# Fetch all tags (for scripting)
$ deputy list docker://library/nginx/ --all

# List images from local Docker daemon (fast, no rate limits)
$ deputy list docker://nginx/ --source docker-daemon
$ deputy list docker://mycompany/myapp/ --source daemon

# Limit total results
$ deputy list docker://library/nginx/ --limit 50

# Manual pagination
$ deputy list docker://library/nginx/ --page-size 50

# Filter with CEL expressions
$ deputy list docker://library/alpine/ --filter 'name.startsWith("3.")'

# Quick mode (skip metadata fetching for faster listing)
$ deputy list docker://library/nginx/ --quick

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

# Fetch all repos (for scripting)
$ deputy list github://anthropics/ --all

# Limit total results
$ deputy list github://anthropics/ --limit 50

# Manual pagination
$ deputy list github://anthropics/ --page-size 10

# Filter with CEL expressions
$ deputy list github://golang/ --filter 'name.contains("tools")'
$ deputy list github://hashicorp/ --filter 'metadata["stars"] > "100"'

# JSON output with metadata (stars, language, topics)
$ deputy list github://golang/ -f json | jq '.discovered_targets[] | {name, stars: .metadata.stars}'
```

**Authentication:** Set `GITHUB_TOKEN` environment variable for higher rate limits and access to private repositories.

### GitHub Repository Collections

List branches and tags in a specific repository:

```console
# List all refs (branches + tags) in a repository
$ deputy list github://kubernetes/kubectl/

# List only branches
$ deputy list github://kubernetes/kubectl/branches/

# List only tags
$ deputy list github://kubernetes/kubectl/tags/

# Alternative URL formats
$ deputy list github.com/golang/go/tags/
$ deputy list https://github.com/docker/cli/branches/

# Filter with CEL expressions
$ deputy list github://golang/go/tags/ --filter 'name.startsWith("go1.22")'
$ deputy list github://rust-lang/rust/branches/ --filter 'metadata["protected"] == "true"'

# JSON output with metadata (sha, ref_type, protected)
$ deputy list github://kubernetes/kubectl/tags/ -f json | jq '.discovered_targets[] | {name, sha: .metadata.sha}'
```

**Note:** The trailing slash indicates a collection. Each discovered ref is returned as a URI like `github://owner/repo@ref` that can be scanned for packages.

**Metadata available in JSON output:** `owner`, `repo`, `ref`, `ref_type` (branch/tag), `sha`, `protected` (for branches), `tarball_url`, `zipball_url` (for tags)

### GitHub Releases

List releases in a repository (useful for tracking software versions and supply chain artifacts):

```console
# List releases in a repository
$ deputy list github://kubernetes/kubectl/releases/

# Filter to stable releases (exclude prereleases)
$ deputy list github://kubernetes/kubectl/releases/ --filter 'metadata["prerelease"] != "true"'

# JSON output with full release metadata
$ deputy list github://hashicorp/vault/releases/ -f json | jq '.discovered_targets[] | {name, published: .created_at, assets: .metadata.asset_count}'
```

**Metadata available:** `owner`, `repo`, `tag_name`, `target_commitish`, `prerelease`, `draft`, `author`, `asset_count`, `html_url`, `tarball_url`, `zipball_url`

### GitHub Release Assets

List assets attached to a specific release (binaries, archives, checksums, SBOMs):

```console
# List assets in a specific release
$ deputy list github://golang/go/releases/go1.22.0/

# List assets for a CLI tool release
$ deputy list github://hashicorp/terraform/releases/v1.7.0/

# Filter to only binaries
$ deputy list github://cli/cli/releases/v2.40.0/ --filter 'metadata["asset_type"].contains("binary")'

# Filter to SBOMs and attestations
$ deputy list github://sigstore/cosign/releases/v2.2.0/ --filter 'metadata["asset_type"] == "sbom" || metadata["asset_type"] == "attestation"'

# JSON output with download URLs for scripting
$ deputy list github://golang/go/releases/go1.22.0/ -f json | jq '.discovered_targets[] | {name, url: .metadata.download_url, type: .metadata.asset_type}'

# Find linux binaries to scan
$ deputy list github://cli/cli/releases/v2.40.0/ --filter 'metadata["asset_type"] == "linux-binary"' -f json | \
    jq -r '.discovered_targets[].metadata.download_url'
```

**Asset types detected:** `linux-binary`, `macos-binary`, `windows-binary`, `binary`, `tarball`, `zip`, `checksum`, `signature`, `sbom`, `attestation`, `container-image`, `json`, `file`

**Metadata available:** `owner`, `repo`, `release_tag`, `asset_type`, `content_type`, `size`, `download_url`, `download_count`, `label`

<!-- TODO: Future enhancement - scan assets directly:
  - github://owner/repo/releases/v1.0.0/app.zip → download, extract, scan binary inside
This would enable complete supply chain verification from source to deployed artifact. -->

### GitHub Commits

List recent commits in a repository (useful for auditing changes and supply chain provenance):

```console
# List commits in a repository (default branch)
$ deputy list github://kubernetes/kubectl/commits/

# Filter commits by author email domain
$ deputy list github://hashicorp/vault/commits/ --filter 'metadata["author_email"].endsWith("@hashicorp.com")'

# JSON output with commit details
$ deputy list github://golang/go/commits/ -f json | jq '.discovered_targets[] | {sha: .metadata.sha, author: .metadata.author, message: .description}'
```

**Metadata available:** `owner`, `repo`, `sha`, `author`, `author_email`, `committer`, `committer_email`, `html_url`, `verified` (GPG signature status)

### GitHub Contributors

List repository contributors (useful for understanding project health and bus factor):

```console
# List contributors to a repository
$ deputy list github://kubernetes/kubectl/contributors/

# JSON output with contribution counts
$ deputy list github://hashicorp/vault/contributors/ -f json | jq '.discovered_targets[] | {login: .name, contributions: .metadata.contributions}'
```

**Metadata available:** `owner`, `repo`, `login`, `contributions`, `avatar_url`, `html_url`, `type` (User/Bot)

### GitHub Collaborators

List repository collaborators (useful for access auditing):

```console
# List collaborators on a repository
$ deputy list github://myorg/myrepo/collaborators/

# Filter by permission level
$ deputy list github://myorg/myrepo/collaborators/ --filter 'metadata["permission"] == "admin"'
```

**Note:** Requires appropriate repository access permissions.

**Metadata available:** `owner`, `repo`, `login`, `permission`, `avatar_url`, `html_url`, `type`

### GitHub Forks

List repository forks (useful for understanding ecosystem and potential supply chain risks):

```console
# List forks of a repository
$ deputy list github://kubernetes/kubectl/forks/

# JSON output with fork details
$ deputy list github://hashicorp/vault/forks/ -f json | jq '.discovered_targets[] | {full_name: .metadata.full_name, owner: .metadata.fork_owner}'
```

**Metadata available:** `owner`, `repo`, `fork_owner`, `full_name`, `default_branch`, `stars`, `html_url`, `created_at`, `pushed_at`

### GitHub Pull Requests

List pull requests (useful for code review auditing and supply chain analysis):

```console
# List open pull requests
$ deputy list github://kubernetes/kubectl/pulls/

# List all pull requests (including closed)
$ deputy list github://kubernetes/kubectl/pulls/ --all

# Filter by state
$ deputy list github://hashicorp/vault/pulls/ --filter 'metadata["state"] == "open"'

# JSON output with PR details
$ deputy list github://golang/go/pulls/ -f json | jq '.discovered_targets[] | {number: .name, title: .description, author: .metadata.user}'
```

**Metadata available:** `owner`, `repo`, `number`, `state`, `user`, `head_ref`, `head_sha`, `base_ref`, `draft`, `mergeable_state`, `html_url`

### GitHub Issues

List issues (useful for security issue tracking):

```console
# List open issues
$ deputy list github://kubernetes/kubectl/issues/

# Filter to security-labeled issues
$ deputy list github://hashicorp/vault/issues/ --filter 'metadata["labels"].contains("security")'

# JSON output with issue details
$ deputy list github://golang/go/issues/ -f json | jq '.discovered_targets[] | {number: .name, title: .description, labels: .metadata.labels}'
```

**Metadata available:** `owner`, `repo`, `number`, `state`, `user`, `labels`, `assignees`, `milestone`, `html_url`

### GitHub Actions Workflows

List workflow definitions (useful for CI/CD supply chain auditing):

```console
# List workflows in a repository
$ deputy list github://kubernetes/kubectl/workflows/

# JSON output with workflow details
$ deputy list github://hashicorp/vault/workflows/ -f json | jq '.discovered_targets[] | {name, state: .metadata.state, path: .metadata.path}'
```

**Metadata available:** `owner`, `repo`, `workflow_id`, `state`, `path`, `html_url`, `badge_url`

### GitHub Workflow Runs

List workflow runs (useful for build provenance and CI/CD auditing):

```console
# List recent workflow runs
$ deputy list github://kubernetes/kubectl/actions/runs/

# Alternative: runs/
$ deputy list github://kubernetes/kubectl/runs/

# Filter by status
$ deputy list github://hashicorp/vault/actions/runs/ --filter 'metadata["status"] == "completed"'

# Filter by conclusion
$ deputy list github://hashicorp/vault/actions/runs/ --filter 'metadata["conclusion"] == "success"'

# JSON output with run details
$ deputy list github://golang/go/actions/runs/ -f json | jq '.discovered_targets[] | {run_number: .name, workflow: .metadata.workflow_name, status: .metadata.status}'
```

**Metadata available:** `owner`, `repo`, `run_id`, `run_number`, `workflow_name`, `workflow_id`, `event`, `status`, `conclusion`, `head_branch`, `head_sha`, `actor`, `html_url`

### GitHub Security Alerts

Deputy supports listing all three types of GitHub Advanced Security alerts with canonical, idiomatic URIs:

#### Dependabot Alerts (Dependency Vulnerabilities)

```console
# List Dependabot alerts for a repository (canonical URI)
$ deputy list github://myorg/myrepo/dependabot/

# Filter by severity
$ deputy list github://myorg/myrepo/dependabot/ --filter 'metadata["severity"] == "critical"'

# Filter by ecosystem
$ deputy list github://myorg/myrepo/dependabot/ --filter 'metadata["ecosystem"] == "npm"'

# JSON output with alert details
$ deputy list github://myorg/myrepo/dependabot/ -f json | jq '.discovered_targets[] | {package: .metadata.package, severity: .metadata.severity, cve: .metadata.cve}'
```

**Metadata available:** `owner`, `repo`, `number`, `state`, `severity`, `cve`, `package`, `ecosystem`, `manifest`

#### Code Scanning Alerts (CodeQL, SARIF)

List code scanning findings from CodeQL, Semgrep, or any SARIF-based scanner:

```console
# List code scanning alerts (canonical URI)
$ deputy list github://myorg/myrepo/code-scanning/

# Filter by severity
$ deputy list github://myorg/myrepo/code-scanning/ --filter 'metadata["rule_severity"] == "error"'

# Filter by tool (e.g., CodeQL vs custom SARIF)
$ deputy list github://myorg/myrepo/code-scanning/ --filter 'metadata["tool"] == "CodeQL"'

# Filter by state (open, dismissed, fixed)
$ deputy list github://myorg/myrepo/code-scanning/ --filter 'metadata["state"] == "open"'

# JSON output with finding details
$ deputy list github://myorg/myrepo/code-scanning/ -f json | jq '.discovered_targets[] | {rule: .metadata.rule_id, severity: .metadata.rule_severity, file: .metadata.file, line: .metadata.line}'
```

**Metadata available:** `owner`, `repo`, `number`, `state`, `rule_id`, `rule_severity`, `tool`, `tool_version`, `file`, `line`, `ref`, `dismissed_by`, `dismissed_reason`

#### Secret Scanning Alerts

List detected secrets and credentials:

```console
# List secret scanning alerts (canonical URI)
$ deputy list github://myorg/myrepo/secret-scanning/

# Filter by secret type
$ deputy list github://myorg/myrepo/secret-scanning/ --filter 'metadata["secret_type"].contains("aws")'

# Filter to open (unresolved) secrets
$ deputy list github://myorg/myrepo/secret-scanning/ --filter 'metadata["state"] == "open"'

# Find secrets that bypassed push protection
$ deputy list github://myorg/myrepo/secret-scanning/ --filter 'metadata["push_protection_bypassed"] == "true"'

# JSON output with secret details
$ deputy list github://myorg/myrepo/secret-scanning/ -f json | jq '.discovered_targets[] | {type: .metadata.secret_type, state: .metadata.state}'
```

**Metadata available:** `owner`, `repo`, `number`, `state`, `secret_type`, `resolution`, `resolved_by`, `push_protection_bypassed`, `bypassed_by`

**Note:** All security alert types require appropriate repository permissions. Dependabot alerts require `vulnerability_alerts` read access. Code scanning and secret scanning alerts require `security_events` read access.

### GitHub Security Advisories

List repository security advisories (for maintainers publishing security fixes):

```console
# List security advisories
$ deputy list github://myorg/myrepo/advisories/

# Filter by severity
$ deputy list github://myorg/myrepo/advisories/ --filter 'metadata["severity"] == "high"'

# JSON output with advisory details
$ deputy list github://myorg/myrepo/advisories/ -f json | jq '.discovered_targets[] | {ghsa: .name, summary: .description, severity: .metadata.severity}'
```

**Metadata available:** `owner`, `repo`, `ghsa_id`, `cve_id`, `severity`, `state`, `author`, `cvss_score`, `cvss_vector`

### GitHub Packages

List packages published to GitHub Packages (useful for supply chain inventory and artifact tracking):

```console
# List all packages in an organization
$ deputy list github://myorg/packages/

# List packages for a user
$ deputy list github://myuser/packages/

# List packages linked to a specific repository
$ deputy list github://myorg/myrepo/packages/

# Filter by package type (container, npm, maven, rubygems, nuget)
$ deputy list github://myorg/packages/ --filter 'metadata["package_type"] == "container"'

# Filter by visibility
$ deputy list github://myorg/packages/ --filter 'metadata["visibility"] == "public"'

# JSON output with package details
$ deputy list github://myorg/packages/ -f json | jq '.discovered_targets[] | {name, type: .metadata.package_type, versions: .metadata.version_count}'

# Find what packages a specific repo publishes
$ deputy list github://myorg/myrepo/packages/ -f json | jq '.discovered_targets[].name'
```

**URI patterns:**
- `github://owner/packages/` - List all packages in an org/user
- `github://owner/repo/packages/` - List packages linked to a specific repository

**Package types supported:** `container` (ghcr.io), `npm`, `maven`, `rubygems`, `nuget`, `docker`

**Metadata available:** `owner`, `owner_login`, `owner_type`, `package_type`, `visibility`, `version_count`, `repository` (linked repo), `updated_at`

**Note:** Requires a `GITHUB_TOKEN` with `read:packages` scope for private packages.

### GitHub Enterprise Organizations

List organizations within a GitHub Enterprise (requires enterprise admin access):

```console
# List organizations in an enterprise
$ deputy list github://enterprises/my-enterprise/

# Alternative: singular form
$ deputy list github://enterprise/my-enterprise/

# JSON output with org details
$ deputy list github://enterprises/my-enterprise/ -f json | jq '.discovered_targets[] | {login: .name, description}'
```

**Note:** Requires a `GITHUB_TOKEN` with `enterprise:read` scope or enterprise admin access.

**Metadata available:** `enterprise`, `type`, `login`, `display_name`, `avatar_url`

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

# Scan all release tags in a repo
$ deputy list github://kubernetes/kubectl/tags/ -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -P4 -I{} deputy scan {}

# Hierarchical discovery: org -> repos -> latest tag -> scan
$ deputy list github://myorg/ -f json | \
    jq -r '.discovered_targets[].uri' | \
    while read repo; do
      tag=$(deputy list "${repo}/" -f json --page-size 1 | jq -r '.discovered_targets[0].uri // empty')
      [ -n "$tag" ] && deputy scan "$tag"
    done

# List AMIs and scan each one
$ deputy list aws://amis?owner=self -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -I{} deputy scan {}

# Scan all prod AMIs
$ deputy list aws://amis?owner=self&tags.env=prod -f json | \
    jq -r '.discovered_targets[].uri' | \
    xargs -P4 -I{} deputy scan {} --format json
```

### Supply Chain Security Auditing

Deputy's comprehensive GitHub listing enables thorough supply chain security investigations:

```console
# Audit an organization's supply chain attack surface
# 1. List all repos and their contributors
$ for repo in $(deputy list github://myorg/ -f json | jq -r '.discovered_targets[].name'); do
    echo "=== $repo contributors ==="
    deputy list "github://myorg/$repo/contributors/" -f json | \
      jq -r '.discovered_targets[] | "\(.name) (\(.metadata.contributions) commits)"'
  done

# 2. Check for critical security alerts across all three types
$ for repo in $(deputy list github://myorg/ -f json | jq -r '.discovered_targets[].name'); do
    # Dependabot alerts (dependency vulnerabilities)
    dep_alerts=$(deputy list "github://myorg/$repo/dependabot/" -f json 2>/dev/null | \
      jq '[.discovered_targets[] | select(.metadata.severity == "critical")] | length')
    # Code scanning alerts (CodeQL/SARIF)
    code_alerts=$(deputy list "github://myorg/$repo/code-scanning/" -f json 2>/dev/null | \
      jq '[.discovered_targets[] | select(.metadata.rule_severity == "error")] | length')
    # Secret scanning alerts
    secret_alerts=$(deputy list "github://myorg/$repo/secret-scanning/" -f json 2>/dev/null | \
      jq '[.discovered_targets[] | select(.metadata.state == "open")] | length')
    [ "$dep_alerts" != "0" ] && echo "$repo: $dep_alerts critical dependency alerts"
    [ "$code_alerts" != "0" ] && echo "$repo: $code_alerts high-severity code findings"
    [ "$secret_alerts" != "0" ] && echo "$repo: $secret_alerts open secret alerts"
  done

# 3. Audit workflow security (look for untrusted actions)
$ deputy list github://myorg/myrepo/workflows/ -f json | \
    jq -r '.discovered_targets[].metadata.path' | \
    xargs -I{} grep -l "uses:" {}

# 4. Track release provenance via workflow runs
$ deputy list github://myorg/myrepo/releases/ -f json | \
    jq -r '.discovered_targets[] | "\(.name): published \(.created_at)"'

# 5. Identify external collaborators
$ deputy list github://myorg/myrepo/collaborators/ -f json | \
    jq '.discovered_targets[] | select(.metadata.type != "Bot") | {login: .name, permission: .metadata.permission}'

# 6. Monitor for suspicious fork activity
$ deputy list github://myorg/myrepo/forks/ -f json | \
    jq '.discovered_targets[] | {owner: .metadata.fork_owner, created: .created_at}'

# 7. Audit commit signing (GPG verification)
$ deputy list github://myorg/myrepo/commits/ -f json | \
    jq '.discovered_targets[] | select(.metadata.verified != "true") | {sha: .metadata.sha, author: .metadata.author}'

# Enterprise-wide audit: list all orgs and their repos
$ for org in $(deputy list github://enterprises/my-enterprise/ -f json | jq -r '.discovered_targets[].name'); do
    echo "=== $org ==="
    deputy list "github://$org/" -f json | jq -r '.discovered_targets[].name'
  done

# 8. Inventory all published packages in an org
$ deputy list github://myorg/packages/ -f json | \
    jq '.discovered_targets[] | {name, type: .metadata.package_type, versions: .metadata.version_count}'

# 9. Find container packages that might need vulnerability scanning
$ deputy list github://myorg/packages/ --filter 'metadata["package_type"] == "container"' -f json | \
    jq -r '.discovered_targets[].name' | \
    xargs -I{} deputy scan "ghcr.io/myorg/{}"
```

## Output

### Collection Output (Text Format)

When listing a collection, output shows discovered targets. The columns shown depend on available metadata.

**Container Registry (tags):**

```
TAG        DIGEST              CREATED
3.19.0     sha256:af4785c02...  2024-01-15
3.19.1     sha256:c5c5fda71...  2024-02-20
3.18.6     sha256:1875c923b...  2024-01-10
latest     sha256:c5c5fda71...  2024-02-20

Summary:
  4 tags discovered
```

When digest/created metadata isn't available (e.g., due to rate limiting):

```
TAG
3.19.0
3.19.1
3.18.6
latest

Summary:
  4 tags discovered

  Tip: Use -f json for full details (digest, created_at, URI)
```

**GitHub Organization (repos):**

```
REPO                            STARS  LANGUAGE    CREATED
sdk-go                          521    Go          2019-10-17
sdk-java                        423    Java        2019-10-17
temporal                        8234   Go          2019-10-16
samples-go                      312    Go          2019-10-17

Summary:
  4 repositories discovered
```

**GitHub Repository (refs):**

```
REF           TYPE    SHA
main          branch  a1b2c3d
develop       branch  e4f5g6h
v1.0.0        tag     i7j8k9l
v1.1.0        tag     m0n1o2p

Summary:
  4 refs discovered
```

**AWS Resources:**

```
NAME                            CREATED
my-app-v1.2.3                   2024-01-15
my-app-v1.2.2                   2024-01-10
base-image-v1.0.0               2023-12-01

Summary:
  3 resources discovered
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

Container images show system packages. By default, the DIRECT column is hidden since the direct/indirect concept doesn't apply to container package managers (APK, DEB, RPM):

```
PURL
pkg:apk/alpine/alpine-baselayout-data@3.4.3-r2?arch=x86_64&distro=3.19.9
pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=3.19.9
pkg:apk/alpine/musl@1.2.4_git20230717-r5?arch=x86_64&distro=3.19.9

Summary:
  15 total packages
```

> **Note:** For container images, the direct/indirect distinction requires base image detection via `deputy scan --detect-base-image`. This queries deps.dev to determine which packages came from your base image (indirect) versus packages you added in your Dockerfile (direct). See [scan command](scan.md#base-image-detection) for details.

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

### Container Registry Listing Performance

When listing tags in a container registry collection, Deputy fetches metadata (digest, created_at) for each tag by default. For repositories with many tags, this can be slow due to the number of API calls.

**Use `--quick` for faster listing:**

```console
# Default: fetches digest and created_at for each tag (slower but richer metadata)
$ deputy list docker://library/alpine/

# Quick mode: only lists tag names (faster, no extra API calls)
$ deputy list docker://library/alpine/ --quick
```

The `--quick` flag is useful when:
- You only need tag names, not digests or timestamps
- You're hitting registry rate limits
- You're scanning a repository with hundreds of tags
- You'll scan individual images later anyway (which fetches the digest)

<!-- TODO: Consider implementing optional caching for container registry listings.
Potential approaches:
1. File-based cache with TTL (e.g., ~/.cache/deputy/registry/)
2. In-memory LRU cache for repeated listings within a session
3. Configurable cache duration (fresh tags may appear frequently)
4. Cache invalidation on tag push (out-of-band, webhooks)
Key considerations:
- Cache key: repository + tag → (digest, created_at)
- TTL: short (1-5 min) for tag lists, longer for immutable digests
- Storage: tag lists are small, digests are content-addressable
- Staleness: acceptable for discovery workflows, not for security scans
-->

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

### GitHub Repository Collections

| URI Pattern | Description |
| --- | --- |
| `github://owner/repo/` | List all refs (branches + tags) |
| `github://owner/repo/branches/` | List only branches |
| `github://owner/repo/tags/` | List only tags |
| `github://owner/repo/refs/` | List all refs (explicit) |
| `github://owner/repo/releases/` | List releases |
| `github://owner/repo/releases/v1.0.0/` | List assets in a specific release |
| `github://owner/repo/commits/` | List recent commits |
| `github://owner/repo/contributors/` | List contributors |
| `github://owner/repo/collaborators/` | List collaborators (requires access) |
| `github://owner/repo/forks/` | List repository forks |
| `github://owner/repo/pulls/` | List pull requests |
| `github://owner/repo/issues/` | List issues |
| `github://owner/repo/workflows/` | List Actions workflows |
| `github://owner/repo/actions/runs/` | List workflow runs |
| `github://owner/repo/dependabot/` | List Dependabot alerts (requires access) |
| `github://owner/repo/code-scanning/` | List code scanning alerts (CodeQL/SARIF) |
| `github://owner/repo/secret-scanning/` | List secret scanning alerts |
| `github://owner/repo/advisories/` | List security advisories |
| `github://owner/repo/packages/` | List packages linked to repo |
| `github://owner/packages/` | List all packages in org/user |
| `github.com/owner/repo/tags/` | Alternative format (github.com prefix) |

**Aliases:** `branch` → `branches`, `tag` → `tags`, `release` → `releases`, `commit` → `commits`, `contributor` → `contributors`, `collaborator` → `collaborators`, `fork` → `forks`, `pull` → `pulls`, `pr` → `pulls`, `prs` → `pulls`, `issue` → `issues`, `workflow` → `workflows`, `runs` → `actions/runs`, `dependabot-alerts` → `dependabot`, `codeql` → `code-scanning`, `secrets` → `secret-scanning`, `advisory` → `advisories`, `security-advisories` → `advisories`

**Metadata available in JSON output:** varies by collection type, see examples above

### GitHub Enterprise Collections

| URI Pattern | Description |
| --- | --- |
| `github://enterprises/name/` | List organizations in enterprise |
| `github://enterprise/name/` | Singular form (also supported) |

**Note:** Requires `GITHUB_TOKEN` with `enterprise:read` scope or enterprise admin access.

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
