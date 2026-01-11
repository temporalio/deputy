# Risk Command CLI Mockups

This document shows the proposed CLI UX for the unified supply chain risk analysis feature.

## `deputy risk` - Full Analysis

### Basic Usage

```
$ deputy risk

Supply Chain Risk Analysis
Target: /Users/dev/myproject
Generated: 2024-01-15T10:30:00Z
Dependencies: 234 packages

OVERALL RISK: MEDIUM (Score: 42/100)

SIGNAL BREAKDOWN

  Vulnerabilities  [##########..........] 18/40 pts
                   12 vulns (2 critical, 4 high, 6 medium)
                   2 in KEV, 3 with EPSS > 0.1

  Malicious        [....................] 0/30 pts
                   No malicious packages detected

  Licenses         [####................] 4/10 pts
                   2 copyleft (LGPL-2.1), 1 unknown

  Maintainer       [######..............] 6/10 pts
                   3 stale, 1 deprecated

  Freshness        [####................] 4/5 pts
                   15 outdated (2 major versions behind)

  Secrets          [....................] 0/5 pts
                   No secrets detected

HIGH RISK PACKAGES (Score > 50)
  PURL                                          SCORE  ISSUES
  pkg:npm/lodash@4.17.15                          62   Vulns: 2, Stale
  pkg:golang/golang.org/x/crypto@v0.0.0-...       58   Vulns: 3
  pkg:npm/minimist@1.2.5                          55   Vulns: 1, KEV

TOP RECOMMENDATIONS
  1. [CRITICAL] Update lodash to 4.17.21 (fixes CVE-2021-23337, CVE-2020-8203)
  2. [CRITICAL] Update x/crypto (3 vulnerabilities, 2 in KEV)
  3. [HIGH] Replace deprecated node-uuid with uuid package
  4. [MEDIUM] Update 15 outdated dependencies
  5. [MEDIUM] Add license for 1 unknown package

Policy Evaluation: 2 deny, 3 warn
```

### JSON Output

```
$ deputy risk --format json | jq '.summary'
{
  "overall_score": 42,
  "overall_level": "RISK_LEVEL_MEDIUM",
  "vulnerability_risk": {
    "score": 18,
    "total_count": 12,
    "critical_count": 2,
    "high_count": 4,
    "medium_count": 6,
    "kev_count": 2,
    "high_epss_count": 3
  },
  "malicious_risk": {
    "score": 0,
    "total_count": 0
  },
  "license_risk": {
    "score": 4,
    "copyleft_count": 2,
    "unknown_count": 1
  },
  "maintainer_risk": {
    "score": 6,
    "stale_count": 3,
    "deprecated_count": 1
  },
  "freshness_risk": {
    "score": 4,
    "outdated_count": 15,
    "major_behind_count": 2
  },
  "secrets_risk": {
    "score": 0,
    "total_count": 0
  }
}
```

### Quick Mode (Skip Slow Enrichments)

```
$ deputy risk --quick

Supply Chain Risk Analysis (Quick Mode)
Target: /Users/dev/myproject
Dependencies: 234 packages

OVERALL RISK: MEDIUM (Score: 38/100)

Note: Quick mode skips EPSS/KEV enrichment and some license lookups.
Run without --quick for complete analysis.

  Vulnerabilities  [########............] 15/40 pts
  Malicious        [....................] 0/30 pts
  Licenses         [##..................] 2/10 pts
  Maintainer       [....................] 0/10 pts  (skipped)
  Freshness        [####................] 4/5 pts
  Secrets          [....................] 0/5 pts   (skipped)

HIGH RISK PACKAGES (Score > 50)
  pkg:npm/lodash@4.17.15                          55   Vulns: 2
  pkg:golang/golang.org/x/crypto@v0.0.0-...       52   Vulns: 3
```

### Container Image Analysis

```
$ deputy risk nginx:1.25

Supply Chain Risk Analysis
Target: docker://nginx:1.25
Platform: linux/amd64
Layers: 7

OVERALL RISK: LOW (Score: 18/100)

SIGNAL BREAKDOWN

  Vulnerabilities  [####................] 8/40 pts
                   Base image: 5 (debian:bookworm-slim)
                   Application: 3 (nginx packages)
                   0 in KEV

  Malicious        [....................] 0/30 pts
                   Clean

  Licenses         [....................] 0/10 pts
                   All permissive (BSD, MIT)

  Maintainer       [....................] 0/10 pts
                   nginx: HEALTHY (official image)

  Freshness        [##..................] 2/5 pts
                   3 packages slightly outdated

  Secrets          [....................] 0/5 pts
                   No secrets detected

LAYER BREAKDOWN
  Layer 0 (base)    5 vulns   debian:bookworm-slim
  Layer 1           0 vulns   nginx installation
  Layer 2           3 vulns   nginx modules
  Layers 3-6        0 vulns   configuration

RECOMMENDATIONS
  1. [MEDIUM] Update base image to debian:bookworm-20240115-slim
  2. [LOW] Consider distroless base for smaller attack surface
```

### With Policy Evaluation

```
$ deputy risk --policy policy/examples/risk-analysis-policies.yaml

Supply Chain Risk Analysis
Target: /Users/dev/myproject

OVERALL RISK: HIGH (Score: 62/100)

...

POLICY EVALUATION

  DENY  critical-risk-gate
        Supply chain risk is CRITICAL - immediate action required

  DENY  kev-vulnerability-gate
        2 vulnerabilities are actively exploited (CISA KEV)

  WARN  abandoned-dependency-gate
        3 packages appear abandoned (no activity in 2+ years)

  WARN  freshness-gate
        15 packages are major versions behind

Exit Code: 1 (policy violations)
```

## `deputy investigate` - Deep Dive

### Basic Package Investigation

```
$ deputy investigate lodash

Package Investigation: lodash
PURL: pkg:npm/lodash@4.17.15
================================================================================

RISK ASSESSMENT
  Overall Score: 62/100 (HIGH)

  +-- Vulnerability Risk:  28/40  ##############......
  |     CVE-2021-23337 [HIGH] Prototype pollution
  |       EPSS: 0.42  SSVC: Attend  Fix: 4.17.21
  |     CVE-2020-8203 [HIGH] Prototype pollution
  |       EPSS: 0.38  SSVC: Attend  Fix: 4.17.19
  |
  +-- Malicious Risk:       0/30  ....................
  |     Clean (last scanned: 2024-01-14)
  |
  +-- License Risk:         0/10  ....................
  |     MIT - Permissive
  |
  +-- Maintainer Risk:      4/10  ########............
  |     Status: STALE (no release in 8 months)
  |     Last commit: 45 days ago
  |     Maintainers: 2
  |
  +-- Freshness Risk:       4/5   ################....
        Current: 4.17.15 (18 months old)
        Latest: 4.17.21 (8 months old)
        6 versions behind

DEPENDENCY PATH
  lodash@4.17.15
  +-- express@4.17.1 [package.json]
      +-- your-project

USED BY IN YOUR PROJECT
  express, webpack, babel-core (3 packages)

RECOMMENDED ACTIONS
  1. [CRITICAL] Update to 4.17.21 (fixes 2 HIGH vulnerabilities)
  2. [MEDIUM] Consider lodash-es for ES module support
  3. [INFO] Monitor for maintainer activity

ALTERNATIVES
  PACKAGE              RISK  API SIMILARITY  MIGRATION
  lodash-es@4.17.21      62  Identical      Easy
  just-*@latest          15  Partial        Medium (micro-utilities)
  native ES2020+          0  Partial        Medium (no library needed)
```

### With Version History

```
$ deputy investigate lodash --with-history

...

VERSION RISK HISTORY
  VERSION   SCORE  DATE         VULNS  NOTES
  4.17.21      15  2021-02-20       0  Current stable, all vulns fixed
  4.17.20      25  2020-08-13       1  CVE-2020-28500 fixed
  4.17.19      35  2020-07-15       1  CVE-2020-8203 fixed
  4.17.18      45  2020-04-27       2  +CVE-2020-8203
  4.17.15      62  2019-07-18       2  Your version
  4.17.11      70  2018-04-25       3  +CVE-2019-10744
  ...

  Risk trend: Decreasing (updates reduce risk)
  Recommendation: Update to 4.17.21
```

### With Alternatives Analysis

```
$ deputy investigate lodash --with-alternatives

...

ALTERNATIVES ANALYSIS

  lodash-es@4.17.21
    Risk Score: 15/100 (LOW)
    API Similarity: 100% (identical)
    Migration Difficulty: Easy
    Notes: ES modules version of lodash, same API and maintainers.
           Better tree-shaking support.

  just-clone@5.0.1, just-filter@4.0.1, ...
    Risk Score: 12/100 (LOW)
    API Similarity: 60% (partial)
    Migration Difficulty: Medium
    Notes: Micro-utilities approach. Only import what you use.
           Smaller attack surface, actively maintained.

  Native JavaScript
    Risk Score: 0/100
    API Similarity: 70% (partial)
    Migration Difficulty: Medium
    Notes: ES2020+ includes many lodash features natively:
           - Array.prototype.flat() / flatMap()
           - Object.fromEntries()
           - Optional chaining (?.)
           - Nullish coalescing (??)
```

### Investigating Malicious Package

```
$ deputy investigate event-stream@3.3.6

Package Investigation: event-stream
PURL: pkg:npm/event-stream@3.3.6
================================================================================

!!! MALICIOUS PACKAGE DETECTED !!!

RISK ASSESSMENT
  Overall Score: 100/100 (CRITICAL)

  +-- Vulnerability Risk:   0/40  ....................
  |
  +-- Malicious Risk:      30/30  ####################  DETECTED
  |     Type: COMPROMISED_MAINTAINER
  |     Source: ossf-mal, osv-mal
  |     Advisory: MAL-2018-4028
  |
  |     INDICATORS:
  |     - Legitimate package taken over by malicious actor
  |     - Version 3.3.6 contains cryptocurrency wallet stealer
  |     - Targets copay-dash bitcoin wallet
  |     - Obfuscated payload in flatmap-stream dependency
  |
  |     TIMELINE:
  |     - 2018-09-09: Maintainer rights transferred to unknown actor
  |     - 2018-09-16: Version 3.3.6 published with malicious dependency
  |     - 2018-11-20: Malicious code discovered
  |     - 2018-11-21: Package unpublished from npm
  |
  +-- License Risk:         0/10
  +-- Maintainer Risk:     10/10  COMPROMISED
  +-- Freshness Risk:       5/5   VERY_STALE

DEPENDENCY PATH
  event-stream@3.3.6
  +-- gulp-vinyl-zip@2.1.0 [package.json]
      +-- your-project

IMMEDIATE ACTION REQUIRED
  1. Remove event-stream@3.3.6 from all projects
  2. Audit all code that imported this package
  3. Check for signs of compromise (cryptocurrency wallets)
  4. Update to event-stream@4.0.1 (clean version)
  5. Review dependency update logs for the attack period

SAFE ALTERNATIVES
  readable-stream@3.6.0  - Official Node.js streams implementation
  event-stream@4.0.1     - Clean version (after security audit)
```

## `deputy risk` Progress Output (Streaming)

```
$ deputy risk --verbose

Supply Chain Risk Analysis
Target: /Users/dev/large-project
Dependencies: 1,247 packages

[====                    ] 16%  Extracting inventory...
                              Found 1,247 packages across 8 ecosystems

[========                ] 32%  Analyzing vulnerabilities...
                              Querying OSV database...
                              Found 45 vulnerabilities

[============            ] 48%  Checking malicious packages...
                              Querying OSSF MAL database...
                              Clean

[================        ] 64%  Analyzing licenses...
                              Querying deps.dev...
                              Found 3 issues

[==================      ] 72%  Checking maintainer health...
                              Querying GitHub API...
                              Found 12 stale packages

[====================    ] 80%  Analyzing freshness...
                              Comparing versions...
                              45 outdated packages

[======================  ] 88%  Computing risk scores...
                              Aggregating signals...

[========================] 100% Complete

...

Analysis completed in 23.4s
```

## Command Help

```
$ deputy risk --help

Perform comprehensive supply chain risk analysis.

Analyzes your dependencies across multiple security signals:
- Vulnerabilities (CVEs, GHSAs from OSV)
- Malicious packages (OSSF MAL, typosquats)
- License compliance (SPDX, copyleft detection)
- Maintainer health (abandoned, deprecated)
- Dependency freshness (outdated versions)
- Secrets (leaked credentials)

Usage:
  deputy risk [target] [flags]

Examples:
  # Analyze current repository
  deputy risk

  # Analyze remote repository
  deputy risk github.com/example/repo

  # Analyze container image
  deputy risk nginx:1.25

  # Quick mode (skip slow enrichments)
  deputy risk --quick

  # Focus on specific package
  deputy risk --focus lodash

  # JSON output for CI/CD
  deputy risk --format json

  # With policy evaluation
  deputy risk --policy risk-policy.yaml

Flags:
  -f, --format string           Output format: text, json (default "text")
  -o, --output string           Output file (default stdout)
      --quick                   Skip slow enrichments for faster results
      --focus string            Focus analysis on specific package
      --include-secrets         Include secret scanning (slow)
      --policy stringArray      Policy files to evaluate
      --license-allowlist strings  Allowed SPDX license identifiers
      --license-denylist strings   Forbidden SPDX license identifiers
      --ref string              Git reference for repository targets
      --platform string         Platform for container images
  -h, --help                    Help for risk

Global Flags:
      --debug                   Enable debug logging
      --server string           Remote Deputy server URL
```

```
$ deputy investigate --help

Deep-dive analysis of a single package.

Provides comprehensive information about a package including:
- Full risk assessment breakdown
- Vulnerability details with SSVC prioritization
- Dependency paths (how it enters your project)
- Maintainer health indicators
- Version freshness analysis
- Alternative package suggestions

Usage:
  deputy investigate <package> [flags]

Examples:
  # Investigate by name (uses contextual version)
  deputy investigate lodash

  # Investigate specific version
  deputy investigate pkg:npm/lodash@4.17.21

  # Show what depends on this package
  deputy investigate lodash --with-dependents

  # Show alternative packages
  deputy investigate lodash --with-alternatives

  # Show version history and risk trends
  deputy investigate lodash --with-history

Flags:
      --with-dependents     Show packages that depend on this
      --with-alternatives   Suggest alternative packages
      --with-history        Show version history and risk trends
      --target string       Context for dependency path analysis
  -f, --format string       Output format: text, json (default "text")
  -o, --output string       Output file (default stdout)
  -h, --help                Help for investigate

Global Flags:
      --debug               Enable debug logging
      --server string       Remote Deputy server URL
```
