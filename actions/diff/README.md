# Deputy Diff Action

Compare dependency changes between Git refs with vulnerability analysis.

## Usage

```yaml
- uses: temporalio/deputy/actions/setup@main
- uses: temporalio/deputy/actions/diff@main
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
| `updated-count` | Dependencies updated (upgraded, downgraded, or otherwise changed) |
| `new-vulnerabilities` | Vulnerabilities newly introduced by the change set |
| `policy-denials` | Policy deny results |
| `policy-warnings` | Policy warn results |
| `json-path` | Path to the full structured diff (`deputy diff --format json` output) |
| `summary` | Markdown summary of changes (base64 encoded and bounded for GitHub Actions output limits) |

All counts derive from the structured JSON output (`deputy.diff.v1`). The full
job summary is rendered from the same file via
`deputy diff --from-json ... --format markdown`; the PR comment and base64
`summary` output are structurally truncated when needed for their platform
limits. Use `json-path` with `jq` for complete custom processing:

```yaml
- uses: temporalio/deputy/actions/diff@main
  id: diff
- run: jq '.policy_actions[]? | select(.type == "ACTION_TYPE_DENY")' "${{ steps.diff.outputs.json-path }}"
```

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
      - uses: temporalio/deputy/actions/setup@main
      - uses: temporalio/deputy/actions/diff@main
        with:
          comment-on-pr: true
```

The action automatically fetches the PR base commit if needed - no `fetch-depth: 0` required.

### Compare Tags

```yaml
- uses: temporalio/deputy/actions/diff@main
  with:
    base: v1.0.0
    target: v2.0.0
    comment-on-pr: false
```

### With Policy

```yaml
- uses: temporalio/deputy/actions/diff@main
  with:
    policy: policy/new-dependency-review.yaml
```

### Skip Vulnerability Scan

For faster diff when you only need dependency changes:

```yaml
- uses: temporalio/deputy/actions/diff@main
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
