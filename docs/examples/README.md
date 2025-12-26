# Examples & Transcripts

Real command output and end-to-end workflows.

## Workflow Examples

| Example | Description |
| --- | --- |
| [Pipeline](pipeline.md) | Full `scan → fix → diff → sbom` workflow with output |
| [Time Travel](time-travel.md) | Using Git refs like `@{yesterday}` and `WORKING` |
| [Historical Analysis](historical-analysis.md) | `--as-of` and published date filters |

## Quick Recipes

### Find vulnerabilities introduced this week

```console
$ deputy diff "HEAD@{1.week.ago}" HEAD
```

### Generate SBOM with licenses

```console
$ deputy sbom --licenses --format cyclonedx-json
```

### Check if affected by specific CVE

```console
$ deputy scan | grep CVE-2024-1234
```

### Get JSON for scripting

```console
$ deputy scan --format json | jq '.summary'
$ deputy list --format json | jq '.items | length'
```

### Compare two releases

```console
$ deputy diff v1.0.0 v2.0.0
```

### Historical vulnerability view

```console
$ deputy scan --as-of=2024-06-15
```

## Policy Examples

See the [policy examples](../../policy/examples/) for 30+ ready-to-use policies:

- Severity blocking (`severity-guardrail.yaml`)
- License allowlists (`license-allowlist.yaml`)
- Typosquat detection (`typosquat-levenshtein-guard.yaml`)
- Supply chain controls (`block-package.yaml`)
- Version constraints (`prerelease-guard.yaml`)

## See Also

- [Policy cookbook](../guides/policy-cookbook.md)
- [Command reference](../commands/)
