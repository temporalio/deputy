# Deputy Scan Action

Scan for vulnerabilities and upload results to GitHub Security tab via SARIF.

**Works with or without GitHub Advanced Security (GHAS):**
- With GHAS: Uploads SARIF to GitHub Security tab for rich integration
- Without GHAS: Automatically posts scan summary as PR comment

Every run also writes a **job summary** to the workflow run page: a status
banner, severity counts, and (when scanning to SARIF) a per-finding table
showing each affected package, version, advisory, and the version that fixes
it. No extra configuration is required.

## Usage

```yaml
- uses: temporalio/deputy/actions/setup@main
- uses: temporalio/deputy/actions/scan@main
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Path to scan | `.` |
| `ref` | Git reference to scan | `HEAD` |
| `ecosystems` | Ecosystems to scan (comma-separated) | `all` |
| `format` | Output format (`sarif`, `json`, `text`) | `sarif` |
| `output` | Output file path | `deputy-results.sarif` |
| `ignore-unfixed` | Ignore vulns without fixes | `false` |
| `policy` | Policy file path(s), comma-separated | `''` |
| `upload-sarif` | Upload to GitHub Security | `true` |
| `sarif-category` | SARIF category | `deputy-scan` |
| `github-token` | Token for API access | `${{ github.token }}` |
| `fail-on-findings` | Fail if vulns found | `false` |
| `fail-on-policy-violation` | Fail on policy violations | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif` | Path to SARIF file |
| `findings-count` | Total vulnerabilities |
| `critical-count` | Critical severity count |
| `high-count` | High severity count |
| `policy-violations` | Policy violation count |
| `exit-code` | Deputy exit code |

## Examples

### Basic SARIF Upload

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: temporalio/deputy/actions/setup@main
      - uses: temporalio/deputy/actions/scan@main
```

### With Policy Enforcement

```yaml
- uses: temporalio/deputy/actions/scan@main
  with:
    policy: policy/ci/security-gate.yaml
    fail-on-policy-violation: true
```

### Scan Specific Path

```yaml
- uses: temporalio/deputy/actions/scan@main
  with:
    target: ./backend
    sarif-category: deputy-backend
```

### Multiple Policies

```yaml
- uses: temporalio/deputy/actions/scan@main
  with:
    policy: policy/security.yaml,policy/compliance.yaml
```

## Permissions

For full functionality (SARIF upload with PR comment fallback):

```yaml
permissions:
  security-events: write  # For SARIF upload to GitHub Security tab
  contents: read
  pull-requests: write    # For PR comment fallback when GHAS unavailable
```

If you only have GHAS (or only want PR comments), you can omit the unused permission.

## See Also

- [Setup Action](../setup/README.md) - Install Deputy
- [SBOM Action](../sbom/README.md) - SBOM generation
- [Diff Action](../diff/README.md) - Dependency diff
