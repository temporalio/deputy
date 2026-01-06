# Policy Examples

Ready-to-use CEL policies for common security scenarios. Copy and customize for your needs.

> **Tip**: Start with the [Policy Cookbook](../../docs/guides/policy-cookbook.md) for step-by-step guidance.

## Quick Start

```bash
# Use a policy from this directory
deputy scan --policy policy/examples/severity-guardrail.yaml

# Combine multiple policies
deputy scan --policy policy/examples/severity-guardrail.yaml \
            --policy policy/examples/license-allowlist.yaml

# Test a policy before deployment
deputy policy lint policy/examples/kev-blocker.yaml
```

## Categories

### Vulnerability Management

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [severity-guardrail.yaml](severity-guardrail.yaml) | Block CRITICAL/HIGH severity vulns | `scan_report` |
| [kev-blocker.yaml](kev-blocker.yaml) | Block CISA Known Exploited Vulnerabilities | `scan_vulnerability` |
| [epss-threshold.yaml](epss-threshold.yaml) | Block high exploitation probability (EPSS) | `scan_vulnerability` |
| [exploit-available-blocker.yaml](exploit-available-blocker.yaml) | Block vulns with known exploits | `scan_vulnerability` |
| [no-fix-escalator.yaml](no-fix-escalator.yaml) | Escalate unfixed vulns over time | `scan_vulnerability` |
| [direct-high-fix-block.yaml](direct-high-fix-block.yaml) | Block fixable HIGH in direct deps | `scan_vulnerability` |
| [risk-score-composite.yaml](risk-score-composite.yaml) | Composite risk scoring with EPSS+KEV+severity | `scan_vulnerability` |
| [cwe-injection-blocker.yaml](cwe-injection-blocker.yaml) | Block injection-class CWEs | `scan_vulnerability` |

### License Compliance

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [license-allowlist.yaml](license-allowlist.yaml) | Block copyleft licenses | `scan_vulnerability` |
| [license-allowlist-advisory.yaml](license-allowlist-advisory.yaml) | Warn on non-approved licenses | `scan_vulnerability` |
| [license-allowlist-composed.yaml](license-allowlist-composed.yaml) | Multi-rule license governance | `scan_vulnerability` |
| [license-present-blocker.yaml](license-present-blocker.yaml) | Require license metadata | `scan_vulnerability` |

### Package Governance

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [block-package.yaml](block-package.yaml) | Block specific packages | `scan_vulnerability` |
| [npm-scope-allowlist.yaml](npm-scope-allowlist.yaml) | Only allow approved npm scopes | `npm_artifact_request` |
| [pypi-prefix-allowlist.yaml](pypi-prefix-allowlist.yaml) | Only allow approved PyPI prefixes | `pypi_artifact_request` |
| [gomod-registry-allowlist.yaml](gomod-registry-allowlist.yaml) | Only allow approved Go module paths | `go_artifact_request` |
| [domain-branded-package-guard.yaml](domain-branded-package-guard.yaml) | Block domain typosquat packages | `scan_vulnerability` |
| [typosquat-levenshtein-guard.yaml](typosquat-levenshtein-guard.yaml) | Detect typosquatting via edit distance | `scan_vulnerability` |
| [shai-hulud-npm.yaml](shai-hulud-npm.yaml) | Comprehensive npm malware blocklist | `npm_artifact_request` |

### Version Control

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [min-version.yaml](min-version.yaml) | Require minimum package versions | `scan_vulnerability` |
| [go-downgrade-guard.yaml](go-downgrade-guard.yaml) | Prevent Go module downgrades | `scan_vulnerability` |
| [go-pseudo-version-deny.yaml](go-pseudo-version-deny.yaml) | Block Go pseudo-versions | `go_artifact_request` |
| [prerelease-guard.yaml](prerelease-guard.yaml) | Block prerelease versions | `scan_vulnerability` |
| [unstable-major-guard.yaml](unstable-major-guard.yaml) | Warn on v0.x.x dependencies | `scan_vulnerability` |
| [critical-runtime-pinning.yaml](critical-runtime-pinning.yaml) | Pin runtime deps to exact versions | `scan_vulnerability` |

### Dependency Analysis

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [dependency-count-guard.yaml](dependency-count-guard.yaml) | Limit total dependency count | `scan_report` |
| [new-dependency-review.yaml](new-dependency-review.yaml) | Flag newly added dependencies | `scan_vulnerability` |
| [critical-transitive-spotlight.yaml](critical-transitive-spotlight.yaml) | Highlight critical transitive vulns | `scan_vulnerability` |
| [graph-depth-policy.yaml](graph-depth-policy.yaml) | Policies based on dependency depth | `scan_vulnerability` |

### Container Security

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [container-security.yaml](container-security.yaml) | Comprehensive container policies | `scan_report`, `oci_artifact_request` |
| [container-image-config.yaml](container-image-config.yaml) | Image configuration checks | `scan_report` |
| [container-base-image.yaml](container-base-image.yaml) | Base image governance | `scan_report` |
| [container-layer-vulnerability.yaml](container-layer-vulnerability.yaml) | Layer-aware vuln policies | `scan_vulnerability` |
| [container-diff.yaml](container-diff.yaml) | Container image diff policies | `scan_report` |

### Dockerfile Analysis

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [dockerfile-security.yaml](dockerfile-security.yaml) | Comprehensive Dockerfile policies | `dockerfile_report`, `dockerfile_stage` |

### Proxy & JWT Authentication

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [proxy-critical-advisory.yaml](proxy-critical-advisory.yaml) | Advisory mode for proxy | `*_artifact_request` |
| [jwt-anonymous-guard.yaml](jwt-anonymous-guard.yaml) | Require authentication | `*_artifact_request` |
| [jwt-role-based-access.yaml](jwt-role-based-access.yaml) | Role-based package access | `*_artifact_request` |
| [jwt-service-account.yaml](jwt-service-account.yaml) | Service account restrictions | `*_artifact_request` |
| [jwt-audit-logging.yaml](jwt-audit-logging.yaml) | Audit log policy decisions | `*_artifact_request` |

### GitHub Actions & CI/CD

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [github-actions-oidc.yaml](github-actions-oidc.yaml) | GitHub Actions OIDC claims | `*_artifact_request` |
| [prod-manifest-gate.yaml](prod-manifest-gate.yaml) | Production deployment gates | `scan_report` |

### Remediation & Fix Policies

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [fix-step-command-allowlist.yaml](fix-step-command-allowlist.yaml) | Restrict fix commands | `fix_step` |
| [update-cooloff-policy.yaml](update-cooloff-policy.yaml) | Wait period for new versions | `fix_step` |

### SBOM Quality

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [sbom-metadata-quality.yaml](sbom-metadata-quality.yaml) | SBOM completeness checks | `scan_report` |
| [sbom-size-shape-sanity.yaml](sbom-size-shape-sanity.yaml) | SBOM structural validation | `scan_report` |

### Diff Policies

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [diff.yaml](diff.yaml) | Dependency diff rules | `scan_report` |

### Targeted Blocks

| Policy | Description | Entrypoint |
|--------|-------------|------------|
| [log4shell.yaml](log4shell.yaml) | Block Log4Shell CVE | `scan_vulnerability` |
| [xz-backdoor.yaml](xz-backdoor.yaml) | Block XZ Utils backdoor | `scan_vulnerability` |
| [deny-aws-sdk-v1.yaml](deny-aws-sdk-v1.yaml) | Block deprecated AWS SDK v1 | `scan_vulnerability` |
| [deprecated-module-block.yaml](deprecated-module-block.yaml) | Block deprecated modules | `scan_vulnerability` |

## Complexity Levels

### Starter (Single Rule)

Good for learning CEL and policy basics:
- `severity-guardrail.yaml` — Simple severity check
- `block-package.yaml` — Block by name
- `license-allowlist.yaml` — Basic license filtering

### Intermediate (Multiple Rules)

Combines several checks:
- `kev-blocker.yaml` — KEV + fallback warning
- `risk-score-composite.yaml` — Multi-factor scoring
- `npm-scope-allowlist.yaml` — Scope validation + warnings

### Advanced (Complex Logic)

Production-grade with comprehensive coverage:
- `container-security.yaml` — Full container governance
- `dockerfile-security.yaml` — Dockerfile static analysis
- `shai-hulud-npm.yaml` — Large-scale malware blocklist

## Entrypoint Reference

| Entrypoint | When Evaluated | Key Variables |
|------------|----------------|---------------|
| `scan_vulnerability` | Per vulnerability found | `vulnerability`, `pkg` |
| `scan_report` | After full scan | `vulnerabilities`, `pkg` |
| `go_artifact_request` | Go proxy requests | `request` |
| `npm_artifact_request` | npm proxy requests | `request` |
| `pypi_artifact_request` | PyPI proxy requests | `request` |
| `oci_artifact_request` | OCI registry proxy | `request`, `image` |
| `dockerfile_report` | Dockerfile scan | `dockerfile`, `dockerfile_analysis` |
| `dockerfile_stage` | Per Dockerfile stage | `stage` |
| `fix_step` | Remediation planning | `step` |

See [Policy Framework](../../docs/reference/policy-framework.md) for complete variable documentation.

## See Also

- [Policy Cookbook](../../docs/guides/policy-cookbook.md) — Step-by-step guide
- [Policy Framework](../../docs/reference/policy-framework.md) — Complete reference
- [Policy Spec](../../docs/reference/policy-spec.md) — YAML schema
- [AGENTS.md](../../AGENTS.md) — CEL variable reference
