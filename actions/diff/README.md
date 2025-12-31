# Deputy Diff Action

Compare dependency changes between Git refs with vulnerability analysis.

## Usage

```yaml
- uses: picatz/deputy/actions/setup@main
- uses: picatz/deputy/actions/diff@main
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `base` | Base reference (auto-detects from PR) | `''` (auto) |
| `target` | Target reference | `HEAD` |
| `repo` | Repository path | `.` |
| `skip-vuln-scan` | Skip vulnerability scanning | `false` |
| `licenses` | Include license information | `true` |
| `policy` | Policy file(s) for evaluation | `''` |
| `comment-on-pr` | Add PR comment with summary | `true` |
| `github-token` | Token for PR comments | `${{ github.token }}` |
| `fail-on-new-vulnerabilities` | Fail if new vulns introduced | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `added-count` | Dependencies added |
| `removed-count` | Dependencies removed |
| `updated-count` | Dependencies updated |
| `new-vulnerabilities` | New vulnerabilities introduced |
| `summary` | Text summary of changes |

## Examples

### PR Dependency Review

```yaml
name: Dependency Review
on: pull_request

permissions:
  pull-requests: write
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: picatz/deputy/actions/setup@main
      - uses: picatz/deputy/actions/diff@main
        with:
          comment-on-pr: true
```

The action automatically fetches the PR base commit if needed - no `fetch-depth: 0` required.

### Compare Tags

```yaml
- uses: picatz/deputy/actions/diff@main
  with:
    base: v1.0.0
    target: v2.0.0
    comment-on-pr: false
```

### With Policy

```yaml
- uses: picatz/deputy/actions/diff@main
  with:
    policy: policy/new-dependency-review.yaml
```

### Skip Vulnerability Scan

For faster diff when you only need dependency changes:

```yaml
- uses: picatz/deputy/actions/diff@main
  with:
    skip-vuln-scan: true
    licenses: false
```

## Git History Requirements

**For PRs**: The action automatically fetches the base commit - no special checkout configuration needed.

**For tag comparisons** (e.g., `v1.0.0` to `v2.0.0`): Use `fetch-depth: 0` to ensure tags are available:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Alternatively, fetch only the tags you need:

```yaml
- uses: actions/checkout@v4
- run: git fetch --tags origin v1.0.0 v2.0.0
```

## Permissions

Required for PR comments:

```yaml
permissions:
  pull-requests: write
  contents: read
```

## See Also

- [Setup Action](../setup/README.md) - Install Deputy
- [Scan Action](../scan/README.md) - Vulnerability scanning
- [SBOM Action](../sbom/README.md) - SBOM generation
