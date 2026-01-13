# Unified Supply Chain Risk Analysis Design

## Executive Summary

This document proposes a unified supply chain risk analysis feature for Deputy that combines multiple security signals into a holistic risk assessment. The feature will aggregate vulnerabilities (CVEs, GHSAs), malicious packages (OSSF MAL), license compliance, secrets, maintainer health, and dependency freshness into a single coherent analysis with composite risk scoring.

## Current State Analysis

### Existing Capabilities

Deputy already provides several standalone analysis capabilities:

| Capability | Command | Data Source | Policy Entrypoints |
|------------|---------|-------------|-------------------|
| Vulnerabilities | `deputy scan` | OSV, GHSA, NVD | `scan_report`, `scan_vulnerability` |
| Secrets | `deputy secrets` | Veles, pattern matching | `secrets_report`, `secrets_finding` |
| Dependency Graph | `deputy graph` | OSV-SCALIBR, proxies | `graph_report`, `graph_node`, `graph_edge` |
| Package Inventory | `deputy list` | OSV-SCALIBR | N/A |
| License (partial) | Internal | deps.dev, direct fetch | (via `pkg.licenses` in policies) |
| SBOM Generation | `deputy sbom` | Protobom | `sbom_report`, `sbom_component` |
| Threat Intel | `--enrich` flag | EPSS, CISA KEV | Enriches vulnerability findings |
| SSVC Prioritization | `ssvc()` helper | Derived from vuln data | Available in CEL policies |

### Current Gaps

1. **Malicious Package Detection**: No OSSF MAL integration
2. **Maintainer Health**: No signals for abandoned/compromised packages
3. **Dependency Freshness**: No staleness detection or update lag metrics
4. **Unified View**: No single command combines all signals
5. **Composite Scoring**: Risk score policy (`risk-score-composite.yaml`) exists but is vuln-only
6. **Investigation Workflow**: No deep-dive command for single package analysis

## Proposed Design

### 1. New Command: `deputy risk`

A new command that provides unified supply chain risk analysis.

```bash
# Full analysis of current repository
deputy risk

# Analyze specific target
deputy risk github.com/example/repo
deputy risk nginx:1.25

# Quick mode (skip slow enrichments)
deputy risk --quick

# Focus on specific package
deputy risk --focus lodash

# Machine-readable output
deputy risk --format json
```

**Design Rationale**: A new command (rather than `--comprehensive` flag) because:
- Clear mental model: `scan` = vulnerabilities, `risk` = holistic assessment
- Different output format (risk dashboard vs vulnerability list)
- Different default behavior (slower, more comprehensive)
- Avoids bloating the already-complex `scan` command

### 2. Risk Signal Integration

#### 2.1 Vulnerabilities (Existing)

Already well-supported. Enhancements:
- Always include EPSS/KEV enrichment in risk mode
- Add SSVC decision to each finding

#### 2.2 Malicious Packages (New)

Integrate OpenSSF Package Analysis data:

```protobuf
// api/deputy/malicious/v1/malicious.proto
message MaliciousPackageInfo {
  string purl = 1;
  string ecosystem = 2;
  string name = 3;
  string version = 4;
  MaliciousType type = 5;
  string source = 6;  // e.g., "ossf-mal", "osv-mal"
  repeated string indicators = 7;
  string details = 8;
  google.protobuf.Timestamp detected_at = 9;
}

enum MaliciousType {
  MALICIOUS_TYPE_UNSPECIFIED = 0;
  MALICIOUS_TYPE_MALWARE = 1;
  MALICIOUS_TYPE_TYPOSQUAT = 2;
  MALICIOUS_TYPE_DEPENDENCY_CONFUSION = 3;
  MALICIOUS_TYPE_PROTESTWARE = 4;
  MALICIOUS_TYPE_COMPROMISED_MAINTAINER = 5;
}
```

Data Sources:
- **OSV MAL**: Already in OSV database (ecosystem: "MAL")
- **OSSF Package Analysis**: https://github.com/ossf/package-analysis
- **OpenSSF Malicious Packages repo**: https://github.com/ossf/malicious-packages

#### 2.3 License Compliance (Enhanced)

Current `pkg.licenses` is basic. Enhance with:

```protobuf
message LicenseInfo {
  repeated string spdx_ids = 1;
  LicenseRisk risk_level = 2;
  repeated string conflicts = 3;  // Conflicting with project license
  bool copyleft = 4;
  bool requires_attribution = 5;
  string source = 6;  // "deps.dev", "github", "scancode"
}

enum LicenseRisk {
  LICENSE_RISK_UNSPECIFIED = 0;
  LICENSE_RISK_NONE = 1;       // Permissive (MIT, Apache-2.0, BSD)
  LICENSE_RISK_LOW = 2;        // Weak copyleft (LGPL, MPL)
  LICENSE_RISK_MEDIUM = 3;     // Strong copyleft (GPL)
  LICENSE_RISK_HIGH = 4;       // Restrictive/problematic (AGPL, SSPL)
  LICENSE_RISK_CRITICAL = 5;   // No license, unknown, or forbidden
}
```

#### 2.4 Secrets (Enhanced)

Already supported via `deputy secrets`. For unified view:
- Include secret counts in risk summary
- Show secrets-per-dependency correlation
- Container image: correlate secrets with layers

#### 2.5 Maintainer Health (New)

```protobuf
message MaintainerHealth {
  string purl = 1;
  HealthStatus status = 2;
  int32 days_since_last_release = 3;
  int32 days_since_last_commit = 4;
  int32 open_issues = 5;
  int32 open_security_issues = 6;
  bool archived = 7;
  bool deprecated = 8;
  string deprecation_message = 9;
  int32 maintainer_count = 10;
  repeated string maintainer_emails = 11;  // For bus factor analysis
  double bus_factor_risk = 12;  // 0.0-1.0, higher = riskier
}

enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_STALE = 2;       // No activity in 6+ months
  HEALTH_STATUS_ABANDONED = 3;   // No activity in 2+ years
  HEALTH_STATUS_DEPRECATED = 4;  // Explicitly deprecated
  HEALTH_STATUS_ARCHIVED = 5;    // Repository archived
}
```

Data Sources:
- **deps.dev**: Project metadata, version history
- **GitHub API**: Commit activity, issues, archive status
- **npm deprecation**: `npm view <pkg> deprecated`
- **PyPI classifiers**: Development Status classifiers

#### 2.6 Dependency Freshness (New)

```protobuf
message DependencyFreshness {
  string purl = 1;
  string current_version = 2;
  string latest_version = 3;
  int32 versions_behind = 4;
  int32 major_versions_behind = 5;
  int32 days_since_current_release = 6;
  int32 days_since_latest_release = 7;
  FreshnessRisk risk = 8;
  bool is_prerelease = 9;
  bool is_yanked = 10;
}

enum FreshnessRisk {
  FRESHNESS_RISK_UNSPECIFIED = 0;
  FRESHNESS_RISK_CURRENT = 1;      // Within 1 minor version
  FRESHNESS_RISK_SLIGHTLY_STALE = 2;  // 1-2 minor versions behind
  FRESHNESS_RISK_STALE = 3;        // 1 major version behind
  FRESHNESS_RISK_VERY_STALE = 4;   // 2+ major versions behind
  FRESHNESS_RISK_CRITICAL = 5;     // 3+ major or unmaintained latest
}
```

### 3. Composite Risk Scoring Model

#### 3.1 Per-Package Risk Score

Each package receives a composite risk score (0-100):

```go
type PackageRiskScore struct {
    PURL              string
    TotalScore        float64  // 0-100
    VulnerabilityRisk float64  // 0-40 (max weight)
    MaliciousRisk     float64  // 0-30 (immediate threat)
    LicenseRisk       float64  // 0-10
    MaintainerRisk    float64  // 0-10
    FreshnessRisk     float64  // 0-5
    SecretRisk        float64  // 0-5
    Factors           []RiskFactor
}

type RiskFactor struct {
    Category    string   // "vulnerability", "malicious", etc.
    Severity    string   // "critical", "high", "medium", "low"
    Description string
    Source      string
    Score       float64
}
```

**Scoring Weights:**

| Signal | Max Points | Rationale |
|--------|------------|-----------|
| Vulnerability | 40 | Primary security concern |
| Malicious | 30 | Immediate, severe threat |
| License | 10 | Legal/compliance risk |
| Maintainer | 10 | Long-term risk indicator |
| Freshness | 5 | Update lag correlates with risk |
| Secrets | 5 | Context-dependent severity |

**Scoring Algorithm:**

```
VulnerabilityScore = sum(
    CRITICAL * 10 * (1 + KEV_bonus * 0.5 + EPSS_bonus * 0.3)
    HIGH * 6 * (1 + KEV_bonus * 0.5 + EPSS_bonus * 0.3)
    MEDIUM * 3
    LOW * 1
) capped at 40

MaliciousScore =
    MALWARE: 30
    TYPOSQUAT: 25
    DEP_CONFUSION: 25
    COMPROMISED: 30
    PROTESTWARE: 20

LicenseScore =
    CRITICAL: 10
    HIGH: 7
    MEDIUM: 4
    LOW: 2
    NONE: 0

MaintainerScore =
    ABANDONED: 10
    ARCHIVED: 8
    DEPRECATED: 6
    STALE: 4
    HEALTHY: 0
    + bus_factor_risk * 2

FreshnessScore =
    CRITICAL: 5
    VERY_STALE: 4
    STALE: 3
    SLIGHTLY_STALE: 1
    CURRENT: 0

SecretsScore = min(secrets_in_package * 2, 5)

# Risk Level Override Rules
# Certain conditions automatically escalate the risk level regardless of numeric score:

RiskLevel =
    IF MaliciousScore > 0:
        CRITICAL  # Any malicious package detection = automatic CRITICAL
    ELSE IF VulnerabilityScore >= 30 AND has_kev_vuln:
        CRITICAL  # High vuln score with KEV = automatic CRITICAL
    ELSE IF TotalScore >= 76:
        CRITICAL
    ELSE IF TotalScore >= 51:
        HIGH
    ELSE IF TotalScore >= 26:
        MEDIUM
    ELSE:
        LOW
```

**Override Rules Rationale:**
- **Malicious packages**: Any detection of malware, typosquatting, or compromised maintainers represents an immediate, severe threat that warrants CRITICAL status regardless of other factors. These are not probabilistic risks—they are confirmed attacks.
- **KEV vulnerabilities with high score**: Vulnerabilities in CISA's Known Exploited Vulnerabilities catalog are actively being exploited in the wild, making them critical regardless of the overall score distribution.

#### 3.2 Aggregate Project Risk Score

```protobuf
message ProjectRiskSummary {
  double overall_score = 1;      // 0-100, weighted average
  RiskLevel overall_level = 2;   // CRITICAL, HIGH, MEDIUM, LOW

  // Signal breakdowns
  VulnerabilityRiskSummary vulnerability_risk = 3;
  MaliciousRiskSummary malicious_risk = 4;
  LicenseRiskSummary license_risk = 5;
  MaintainerRiskSummary maintainer_risk = 6;
  FreshnessRiskSummary freshness_risk = 7;
  SecretsRiskSummary secrets_risk = 8;

  // Top contributors
  repeated PackageRiskScore high_risk_packages = 10;

  // Actionable insights
  repeated RiskRecommendation recommendations = 11;
}

enum RiskLevel {
  RISK_LEVEL_UNSPECIFIED = 0;
  RISK_LEVEL_LOW = 1;        // 0-25
  RISK_LEVEL_MEDIUM = 2;     // 26-50
  RISK_LEVEL_HIGH = 3;       // 51-75
  RISK_LEVEL_CRITICAL = 4;   // 76-100
}
```

### 4. Policy Integration

#### 4.1 New Policy Variables

```yaml
# Available in risk_report entrypoint
risk:
  overall_score: float           # 0-100
  overall_level: enum            # risk_level.critical, etc.
  vulnerability_count: int
  malicious_count: int
  license_issues: int
  stale_dependencies: int
  abandoned_dependencies: int

# Available in risk_package entrypoint
package_risk:
  purl: string
  total_score: float
  vulnerability_risk: float
  malicious_risk: float
  license_risk: float
  maintainer_risk: float
  freshness_risk: float
  is_malicious: bool
  is_abandoned: bool
  is_deprecated: bool
  licenses: list(string)
  days_since_update: int
```

#### 4.2 New Entrypoints

```go
// Risk analysis entrypoints
EntrypointRiskReport    Entrypoint = "risk_report"     // Whole-project analysis
EntrypointRiskPackage   Entrypoint = "risk_package"    // Per-package analysis
```

#### 4.3 Example Policies

```yaml
# Comprehensive risk gate for CI/CD
policies:
  - name: supply-chain-risk-gate
    entrypoints: [risk_report]
    rules:
      # Block if overall risk is critical
      - action: deny
        when: risk.overall_level == risk_level.critical
        reason: "Supply chain risk level is critical"

      # Block any malicious packages
      - action: deny
        when: risk.malicious_count > 0
        reason: "Malicious packages detected"

      # Warn on high overall risk
      - action: warn
        when: risk.overall_level == risk_level.high
        reason: "Supply chain risk level is high"

  - name: package-risk-policy
    entrypoints: [risk_package]
    rules:
      # Block malicious packages
      - action: deny
        when: package_risk.is_malicious
        reason: "Package flagged as malicious"

      # Block abandoned direct dependencies
      - action: deny
        when: |
          package_risk.is_abandoned &&
          pkg.direct &&
          package_risk.vulnerability_risk > 0
        reason: "Abandoned dependency with vulnerabilities"

      # Warn on high individual package risk
      - action: warn
        when: package_risk.total_score > 50
        reason: "Package has elevated risk score"

  - name: license-compliance
    entrypoints: [risk_package]
    vars:
      forbidden_licenses: ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"]
    rules:
      - action: deny
        when: |
          package_risk.licenses.exists(l, l in forbidden_licenses)
        reason: "Package uses forbidden license"
```

### 5. Investigation Workflow: `deputy investigate`

Deep-dive analysis of a single package:

```bash
# Investigate a specific package
deputy investigate lodash
deputy investigate pkg:npm/lodash@4.17.21

# Investigate with full context
deputy investigate lodash --with-dependents --with-alternatives
```

**Output includes:**

```
Package: lodash@4.17.21
PURL: pkg:npm/lodash@4.17.21
Risk Score: 45/100 (MEDIUM)

VULNERABILITY ANALYSIS
  CVE-2021-23337 [HIGH] - Prototype pollution (fix: 4.17.21)
  CVE-2020-8203 [HIGH] - Prototype pollution (fix: 4.17.19)
  Total: 2 vulnerabilities (0 critical, 2 high)
  SSVC Decision: Attend

MALICIOUS INDICATORS
  Status: Clean
  Last scanned: 2024-01-15

LICENSE ANALYSIS
  License: MIT
  Risk Level: NONE
  Copyleft: No
  Source: deps.dev

MAINTAINER HEALTH
  Status: HEALTHY
  Last release: 45 days ago (4.17.21 on 2024-01-01)
  Last commit: 12 days ago
  Open issues: 156 (3 security-related)
  Maintainers: 2
  Bus factor risk: LOW

FRESHNESS
  Current: 4.17.21
  Latest: 4.17.21
  Status: CURRENT

WHY IS THIS IN MY GRAPH?
  lodash@4.17.21
  └── express@4.18.2 (direct)
      └── your-project
  └── webpack@5.89.0 (direct)
      └── your-project

  Used by 2 direct dependencies

ALTERNATIVES (similar functionality, lower risk)
  lodash-es@4.17.21 - ES modules version, same API
  native JS - Array.prototype.flatMap, Object.entries, etc.

RECOMMENDATIONS
  1. Update to 4.17.21 to fix prototype pollution vulnerabilities
  2. Consider lodash-es for better tree-shaking
  3. Evaluate if native JS methods can replace usage
```

### 6. Proto API Changes

#### 6.1 New Service: RiskService

```protobuf
// api/deputy/risk/v1/service.proto
service RiskService {
  // AnalyzeRisk performs comprehensive supply chain risk analysis
  rpc AnalyzeRisk(AnalyzeRiskRequest) returns (AnalyzeRiskResponse);

  // InvestigatePackage provides deep-dive analysis of a single package
  rpc InvestigatePackage(InvestigatePackageRequest) returns (InvestigatePackageResponse);

  // StreamRiskAnalysis provides streaming progress for long analyses
  rpc StreamRiskAnalysis(AnalyzeRiskRequest) returns (stream RiskAnalysisProgress);
}

message AnalyzeRiskRequest {
  string target = 1;
  RiskAnalysisOptions options = 2;
}

message RiskAnalysisOptions {
  bool include_vulnerabilities = 1;   // default: true
  bool include_malicious = 2;         // default: true
  bool include_licenses = 3;          // default: true
  bool include_maintainer_health = 4; // default: true
  bool include_freshness = 5;         // default: true
  bool include_secrets = 6;           // default: false (slow)
  bool quick_mode = 7;                // Skip slow enrichments
  repeated string policy_paths = 8;
  string ref = 9;                     // Git ref for repo targets
  string platform = 10;               // Platform for container targets
}

message AnalyzeRiskResponse {
  deputy.target.v1.Target target = 1;
  google.protobuf.Timestamp generated_at = 2;
  ProjectRiskSummary summary = 3;
  repeated PackageRiskAssessment packages = 4;
  repeated deputy.policy.v1.Action policy_actions = 5;
}

message InvestigatePackageRequest {
  string purl = 1;                    // Package to investigate
  string target = 2;                  // Context (repo/image) for graph analysis
  bool include_dependents = 3;        // Show what depends on this
  bool include_alternatives = 4;      // Suggest alternatives
}

message InvestigatePackageResponse {
  PackageRiskAssessment risk = 1;
  repeated DependencyPath paths = 2;  // How this package enters your graph
  repeated string dependents = 3;     // What depends on this in your project
  repeated PackageAlternative alternatives = 4;
  repeated string recommendations = 5;
}
```

### 7. CLI UX Mockups

#### 7.1 `deputy risk` Output

```
Supply Chain Risk Analysis
Target: github.com/example/myapp
Generated: 2024-01-15T10:30:00Z
Dependencies: 234 packages

OVERALL RISK: MEDIUM (Score: 42/100)

SIGNAL BREAKDOWN

  Vulnerabilities  [████████░░░░░░░░░░░░] 18/40 pts
                   12 vulns (2 critical, 4 high, 6 medium)
                   2 in KEV, 3 with EPSS > 0.1

  Malicious        [░░░░░░░░░░░░░░░░░░░░]  0/30 pts
                   No malicious packages detected

  Licenses         [████░░░░░░░░░░░░░░░░]  4/10 pts
                   2 copyleft (LGPL-2.1), 1 unknown

  Maintainer       [██████░░░░░░░░░░░░░░]  6/10 pts
                   3 stale, 1 deprecated

  Freshness        [████░░░░░░░░░░░░░░░░]  4/10 pts
                   15 outdated (2 major versions behind)

  Secrets          [░░░░░░░░░░░░░░░░░░░░]  0/10 pts
                   No secrets detected

HIGH RISK PACKAGES (Score > 50)
  pkg:npm/lodash@4.17.15        Score: 62  Vulns: 2, Stale
  pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718  Score: 58  Vulns: 3
  pkg:npm/minimist@1.2.5        Score: 55  Vulns: 1, KEV

TOP RECOMMENDATIONS
  1. [CRITICAL] Update lodash to 4.17.21 (fixes CVE-2021-23337, CVE-2020-8203)
  2. [CRITICAL] Update x/crypto (3 vulnerabilities, 2 in KEV)
  3. [HIGH] Replace deprecated node-uuid with uuid package
  4. [MEDIUM] Update 15 outdated dependencies
  5. [MEDIUM] Add license for 1 unknown package

Policy Evaluation: 2 deny, 3 warn
```

#### 7.2 `deputy investigate` Output

```
Package Investigation: lodash
PURL: pkg:npm/lodash@4.17.15
─────────────────────────────────────────────────────────

RISK ASSESSMENT
  Overall Score: 62/100 (HIGH)

  ├─ Vulnerability Risk:  28/40  ████████████░░░░░░░░
  │    CVE-2021-23337 [HIGH] Prototype pollution
  │      EPSS: 0.42  SSVC: Attend  Fix: 4.17.21
  │    CVE-2020-8203 [HIGH] Prototype pollution
  │      EPSS: 0.38  SSVC: Attend  Fix: 4.17.19
  │
  ├─ Malicious Risk:       0/30  ░░░░░░░░░░░░░░░░░░░░
  │    Clean (last scanned: 2024-01-14)
  │
  ├─ License Risk:         0/10  ░░░░░░░░░░░░░░░░░░░░
  │    MIT - Permissive
  │
  ├─ Maintainer Risk:      4/10  ████████░░░░░░░░░░░░
  │    Status: STALE (no release in 8 months)
  │    Last commit: 45 days ago
  │    Maintainers: 2
  │
  └─ Freshness Risk:       4/5   ████████████████░░░░
       Current: 4.17.15 (18 months old)
       Latest: 4.17.21 (8 months old)
       6 versions behind

DEPENDENCY PATH
  lodash@4.17.15
  └── express@4.17.1 [go.mod]
      └── your-project

USED BY IN YOUR PROJECT
  express, webpack, babel-core (3 packages)

RECOMMENDED ACTIONS
  1. [CRITICAL] Update to 4.17.21 (fixes 2 HIGH vulnerabilities)
  2. [MEDIUM] Consider lodash-es for ES module support
  3. [INFO] Monitor for maintainer activity

ALTERNATIVES
  lodash-es@4.17.21    Same API, ES modules, same vulns
  just-*@latest        Micro-utilities, lower attack surface
  native ES2020+       Use Array.flat(), Object.fromEntries()
```

### 8. Implementation Plan

#### Phase 1: Foundation (2-3 weeks)
- [ ] Create `api/deputy/risk/v1/` proto definitions
- [ ] Implement `RiskService` with basic analysis
- [ ] Add `deputy risk` command (vulnerability + license only)
- [ ] Add `risk_report`, `risk_package` policy entrypoints

#### Phase 2: Malicious Package Detection (2 weeks)
- [ ] Integrate OSV MAL ecosystem queries
- [ ] Add OSSF malicious-packages data source
- [ ] Implement typosquat detection (levenshtein + popular packages)
- [ ] Add malicious package indicators to risk scoring

#### Phase 3: Maintainer Health (2 weeks)
- [ ] Add deps.dev project metadata queries
- [ ] Implement staleness detection
- [ ] Add GitHub API integration for activity metrics
- [ ] Implement bus factor analysis

#### Phase 4: Freshness Analysis (1 week)
- [ ] Add version comparison across ecosystems
- [ ] Implement freshness scoring
- [ ] Add yanked/deprecated version detection

#### Phase 5: Investigation Workflow (2 weeks)
- [ ] Implement `deputy investigate` command
- [ ] Add alternative package suggestions
- [ ] Add detailed recommendation generation

#### Phase 6: Polish & Documentation (1 week)
- [ ] Add comprehensive policy examples
- [ ] Update AGENTS.md with new variables
- [ ] Add user documentation
- [ ] Performance optimization

### 9. Cross-Target Consistency

The risk model applies consistently across all target types:

| Target Type | Vulnerabilities | Malicious | License | Maintainer | Freshness | Secrets |
|-------------|-----------------|-----------|---------|------------|-----------|---------|
| Repository | Yes | Yes | Yes | Yes | Yes | Yes |
| Container Image | Yes | Yes | Yes* | Partial** | Partial** | Yes |
| SBOM | Yes | Yes | Yes | No*** | No*** | No |
| PURL | Yes | Yes | Yes | Yes | Yes | No |

*License from package metadata, not container labels
**Health/freshness for OS packages is limited
***SBOM lacks sufficient context for these analyses

### 10. Performance Considerations

Risk analysis involves multiple data sources with varying latencies:

| Data Source | Latency | Caching Strategy |
|-------------|---------|------------------|
| OSV API | 100-500ms | 1-hour TTL |
| EPSS/KEV | 50-200ms | 24-hour disk cache |
| deps.dev | 50-200ms | 1-hour memory cache |
| GitHub API | 100-500ms | 1-hour cache, rate limit aware |
| OSSF MAL | 100-300ms | 6-hour disk cache |
| License scan | Variable | Per-version disk cache |

**Quick Mode** (`--quick`): Skips slow enrichments (GitHub API, some license lookups), providing faster but less complete analysis.

### 11. Security Considerations

1. **Rate Limiting**: Respect GitHub API rate limits, use caching
2. **Credential Handling**: GitHub token optional but recommended
3. **Data Validation**: Validate all external data before use
4. **Remote Mode**: Same security model as existing commands (no local access)

### 12. Open Questions

1. Should `deputy risk` be the default recommendation over `deputy scan` for CI/CD?
2. How to handle conflicting signals (e.g., maintained package with vulns vs abandoned package without)?
3. Should risk scores be customizable via configuration?
4. Integration with external risk databases (e.g., GitHub Advisory DB)?

---

## Appendix A: Policy Variable Reference

### risk_report Entrypoint

```yaml
# Variables available in risk_report entrypoint
risk:
  overall_score: float           # 0-100 composite score
  overall_level: enum            # risk_level.critical/high/medium/low
  vulnerability:
    count: int
    critical_count: int
    high_count: int
    kev_count: int
    score: float
  malicious:
    count: int
    packages: list(string)       # PURLs of malicious packages
    score: float
  license:
    issue_count: int
    forbidden_count: int
    unknown_count: int
    copyleft_count: int
    score: float
  maintainer:
    abandoned_count: int
    stale_count: int
    deprecated_count: int
    score: float
  freshness:
    outdated_count: int
    major_behind_count: int
    score: float
  secrets:
    count: int
    high_confidence_count: int
    score: float

packages: list(PackageRiskAssessment)
target: Target
```

### risk_package Entrypoint

```yaml
# Variables available in risk_package entrypoint
package_risk:
  purl: string
  name: string
  version: string
  ecosystem: string
  direct: bool
  total_score: float
  vulnerability_risk: float
  malicious_risk: float
  license_risk: float
  maintainer_risk: float
  freshness_risk: float
  secrets_risk: float

  # Boolean flags for common checks
  is_malicious: bool
  is_abandoned: bool
  is_deprecated: bool
  is_stale: bool
  is_outdated: bool
  has_vulnerabilities: bool
  has_critical_vulns: bool
  has_kev_vulns: bool

  # Details
  licenses: list(string)
  vulnerabilities: list(Finding)
  days_since_update: int
  versions_behind: int
  maintainer_status: string

pkg: Package  # Same as existing pkg variable
target: Target
```

## Appendix B: Risk Score Calculation Examples

### Example 1: High Risk Package

```
lodash@4.17.15
├─ Vulnerability: 28 pts
│   ├─ CVE-2021-23337 (HIGH, EPSS=0.42): 6 * (1 + 0.3*0.42) = 7.6
│   └─ CVE-2020-8203 (HIGH, EPSS=0.38): 6 * (1 + 0.3*0.38) = 6.7
│   Total: 14.3 → capped contribution
├─ Malicious: 0 pts
├─ License (MIT): 0 pts
├─ Maintainer (STALE): 4 pts
└─ Freshness (6 versions behind): 4 pts

Total: 36 pts → MEDIUM risk
```

### Example 2: Critical Risk Package (Malicious Override)

```
event-stream@3.3.6 (hypothetical malicious version)
├─ Vulnerability: 10 pts (1 CRITICAL)
├─ Malicious: 30 pts (COMPROMISED_MAINTAINER)
├─ License (MIT): 0 pts
├─ Maintainer (ABANDONED): 10 pts
└─ Freshness (VERY_STALE): 4 pts

Numeric Score: 54 pts → Would normally be HIGH risk
Final Risk Level: CRITICAL (override triggered by MaliciousScore > 0)

Note: Per the Risk Level Override Rules defined in section 3.1, any package
with MaliciousScore > 0 is automatically classified as CRITICAL regardless
of the numeric score. This ensures malicious packages are never downplayed.
```
