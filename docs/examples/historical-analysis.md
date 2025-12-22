# Historical Vulnerability Analysis

Deputy supports time-window and as-of views so you can answer:

- "What was known at the time?" (avoid retroactive bias)
- "When did a vulnerability become known?"
- "What changed between releases *given knowledge available then*?"

## Date Flags Overview

| Flag | Purpose | Example |
|------|---------|---------|
| `--as-of` | Knowledge cutoff date | `--as-of=2024-06-15` |
| `--published-after` | Vulns published on/after date | `--published-after=2024-01` |
| `--published-before` | Vulns published before date | `--published-before=2024-06` |

**Date formats**: `YYYY`, `YYYY-MM`, `YYYY-MM-DD`, or RFC3339

## `--as-of` (Knowledge Cutoff)

`--as-of` shows vulnerabilities known up to and including a specific date. This lets you see what your security posture looked like at a point in time, avoiding retroactive bias.

```console
# What was known at end of 2024?
$ deputy scan --as-of=2024-12-31

# What was known at start of year?
$ deputy scan --as-of=2024-01-01 --ignore-unfixed

# Compare releases with historical knowledge
$ deputy diff v1.0.0 v2.0.0 --as-of=2024-06-30
```

### Example: Release retrospective

```console
$ deputy scan --ref v2.0.0 --as-of=2024-06-15

Scanned example/repo @ v2.0.0 (abc123d)
  Knowledge cutoff: 2024-06-15

∴ Vulnerabilities Found (as of 2024-06-15):

github.com/example/pkg v1.5.0 [direct]:
  • CVE-2024-1234 [HIGH] (↑ v1.5.3)
    SQL injection in query builder
    Published: 2024-03-20

Vulnerability Summary:
  ! 1 requires immediate attention (critical/high severity)
  ↑ 1 can be fixed by upgrading

Note: 3 additional vulnerabilities were disclosed after 2024-06-15
      Run without --as-of to see current findings.
```

## Published Date Filters (Time Windows)

Filter by when vulnerabilities were published to OSV:

```console
# Only vulns published in 2024
$ deputy scan --published-after=2024 --published-before=2025

# Vulns published in Q1 2024
$ deputy scan --published-after=2024-01 --published-before=2024-04

# Recent disclosures (last 30 days)
$ deputy scan --published-after=2024-11-01

# Combine with diff
$ deputy diff main WORKING --published-after=2024-10-01 --published-before=2025-01-01
```

### Example: New disclosures this month

```console
$ deputy scan --published-after=2024-12-01

Scanned example/repo @ HEAD (def456a)
  Published window: 2024-12-01 to present

∴ Vulnerabilities Found (published since 2024-12-01):

stdlib v1.22.0 [direct]:
  • CVE-2024-45678 [MEDIUM] (↑ v1.22.3)
    Denial of service in net/http
    Published: 2024-12-10

Vulnerability Summary:
  1 new vulnerability disclosed this month
  ↑ 1 can be fixed by upgrading
```

## Practical Workflows

### 1. Post-Incident Review

Understand what was known when an incident occurred:

```console
# Incident occurred 2024-08-20, we shipped v3.1.0 on 2024-08-15
$ deputy scan --ref v3.1.0 --as-of=2024-08-15 --format json > known-at-ship.json
$ deputy scan --ref v3.1.0 --as-of=2024-08-20 --format json > known-at-incident.json

# Find vulns disclosed between ship and incident
$ jq -s '
  (.[0].vulnerabilities | map(.id)) as $shipped |
  (.[1].vulnerabilities | map(.id)) as $incident |
  $incident - $shipped
' known-at-ship.json known-at-incident.json

["CVE-2024-9999"]  # This CVE was disclosed after we shipped
```

### 2. Release Auditing

Compare security posture between releases:

```console
# What vulnerabilities were introduced between v1.0.0 and v2.0.0?
$ deputy diff v1.0.0 v2.0.0

# What was known at v2.0.0 release time?
$ deputy scan --ref v2.0.0 --as-of=2024-09-01

# Generate SBOMs for compliance at each release
$ for tag in v1.0.0 v2.0.0 v3.0.0; do
    deputy sbom --ref "$tag" --output "sbom-$tag.json"
  done
```

### 3. Trend Analysis

Track vulnerability disclosure cadence:

```console
# Monthly vulnerability counts for 2024
$ for month in 01 02 03 04 05 06 07 08 09 10 11 12; do
    count=$(deputy scan --published-after=2024-$month --published-before=2024-$((month+1)) \
      --format json 2>/dev/null | jq '.stats.total // 0')
    echo "2024-$month: $count"
  done

# Output:
# 2024-01: 2
# 2024-02: 0
# 2024-03: 5
# ...
```

### 4. Vulnerability Window Analysis

How long were we exposed to a specific CVE?

```console
# When was CVE-2024-1234 published?
$ deputy scan --format json | jq '.vulnerabilities[] | select(.id == "CVE-2024-1234") | .published'
"2024-03-15"

# When did we upgrade to the fixed version?
$ git log --oneline --all -- go.mod | head -20
# ... find the commit that upgraded the dep

# Or use deputy diff with time-based refs
$ deputy diff "main@{2024-03-01}" "main@{2024-04-01}" | grep -A3 "affected-package"
```

### 5. Zero-Day Response

When a new CVE drops, quickly assess exposure:

```console
# New CVE announced today - are we affected?
$ deputy scan --published-after=$(date +%Y-%m-%d)

# Check all release branches
$ for branch in main release/v1 release/v2; do
    echo "=== $branch ==="
    deputy scan --ref "$branch" --format json | \
      jq --arg cve "CVE-2024-BREAKING" \
        '.vulnerabilities[] | select(.id == $cve)'
  done
```

### 6. Compliance Reporting

Generate point-in-time security reports:

```console
# Quarterly security report - what was our posture at quarter end?
$ deputy scan --as-of=2024-03-31 --format json > q1-2024.json
$ deputy scan --as-of=2024-06-30 --format json > q2-2024.json
$ deputy scan --as-of=2024-09-30 --format json > q3-2024.json
$ deputy scan --as-of=2024-12-31 --format json > q4-2024.json

# Compare quarters
$ jq -s '[.[] | {date: .generated, stats: .stats}]' q*.json
```

## Combining with Other Features

### With policies

```console
# Did we violate the policy at ship time?
$ deputy scan --ref v2.0.0 --as-of=2024-06-15 --policy policy/release-gate.yaml
```

### With diff

```console
# What vulnerabilities were fixed between releases (historical view)?
$ deputy diff v1.0.0 v2.0.0 --as-of=2024-09-01

# What new vulnerabilities were introduced (current knowledge)?
$ deputy diff v1.0.0 v2.0.0
```

### With SBOM

```console
# Generate SBOM with point-in-time vulnerability annotations
$ deputy sbom --ref v2.0.0 --output sbom.json
$ deputy scan --ref v2.0.0 --as-of=2024-06-15 --format json > vulns-at-ship.json
```

## See Also

- [Time Travel](time-travel.md) - Git refs and `WORKING`
- [scan command](../commands/scan.md) - Complete scan reference
- [diff command](../commands/diff.md) - Complete diff reference
