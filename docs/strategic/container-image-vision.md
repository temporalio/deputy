# Deputy Container Image Strategy: World-Class Vision

## Executive Summary

Deputy has strong foundational infrastructure for container image scanning and is actively developing world-class capabilities. This document outlines the strategic vision and tracks progress.

## Current State Assessment

### Implemented Capabilities

1. **Layer-Aware Vulnerability Attribution** - Each vulnerability tagged with `LayerDetails` (index, diffId, chainId, command, inBaseImage)
2. **Rich Image Configuration Extraction** - User, env, sensitive_env detection, entrypoint, cmd, ports, volumes, labels, healthcheck, history
3. **Runtime Proxy Enforcement** - Policy evaluation BEFORE image pull (unique positioning)
4. **Flexible CEL Policy Engine** - Powerful expression language with custom helpers
5. **SBOM Generation** - CycloneDX/SPDX with layer metadata
6. **Container Image Diff** - Full `deputy diff <image1> <image2>` support with layer tracking
7. **ImageInfo in Policies** - `image.config.*`, `image.metadata.*`, `image.history[]` accessible in CEL

### Policy Integration

ImageInfo is wired to policy evaluation via the `image_info` variable, enabling policies like:

```yaml
# Block images running as root
- name: block-root
  entrypoints: [scan_vulnerability]
  rules:
    - action: deny
      when: |
        has(image.config) && image.config.is_root == true &&
        vulnerability.severity == 'CRITICAL'
      reason: "Critical vulnerability in root container"

# Detect sensitive environment variables
- name: no-secrets-in-env
  entrypoints: [scan_report]
  rules:
    - action: deny
      when: |
        has(image.config) && size(image.config.sensitive_env) > 0
      reason: "Secrets detected in image environment"

# Block oversized images
- name: image-size-limit
  entrypoints: [scan_report]
  rules:
    - action: warn
      when: |
        has(image.metadata) && image.metadata.size > 2147483648
      reason: "Image exceeds 2GB size limit"
```

---

## Strategic Differentiation Opportunities

### 1. Base Image Intelligence

**Vision**: Deputy knows which base images are best for security, and can recommend upgrades.

**Capabilities**:
- Track vulnerability density across popular base images
- Alert when chosen base image falls behind alternatives
- Recommend specific base image updates with impact analysis
- Detect when base image is EOL or deprecated

**Policy Examples**:

```yaml
# Require approved base images
- name: approved-bases
  entrypoints: [scan_report, oci_artifact_request]
  vars:
    approvedBases:
      - "docker.io/library/alpine:3.19"
      - "gcr.io/distroless/static-debian12"
  rules:
    - action: deny
      when: |
        has(image.metadata) &&
        !(image.config.labels['base-image'] in approvedBases)
      reason: "Base image not in approved list"

# Block stale base images
- name: base-image-age
  entrypoints: [scan_report]
  rules:
    - action: deny
      when: |
        has(image.metadata) &&
        image.metadata.layer_count > 0 &&
        age(image.history[0].created) > duration('180d')
      reason: "Base image is older than 180 days - update required"
```

### 2. Supply Chain Provenance (Planned)

**Vision**: Deputy validates and enforces supply chain attestations.

**Capabilities** (planned):
- Verify SLSA provenance attestations
- Validate image signatures (cosign, notation)
- Enforce required OCI annotations
- Track builder identity and build timestamp

**Policy Examples** (future):

```yaml
# Require SLSA provenance
- name: require-slsa
  entrypoints: [oci_artifact_request]
  rules:
    - action: deny
      when: |
        !has(image.attestations) ||
        !image.attestations.exists(a, a.predicateType == 'slsa.dev/provenance/v1')
      reason: "SLSA provenance attestation required"

# Require signatures from trusted keys
- name: require-signature
  entrypoints: [oci_artifact_request]
  rules:
    - action: deny
      when: |
        !has(image.signatures) ||
        !image.signatures.exists(s, s.keyId in ['key1', 'key2'])
      reason: "Image must be signed by authorized key"
```

### 3. Build Practice Analysis

**Vision**: Deputy analyzes Dockerfile commands and recommends improvements.

**Capabilities**:
- Detect anti-patterns (unpinned package versions, curl | bash, etc.)
- Score build hygiene (layer consolidation, cache efficiency)
- Track how build practices correlate with vulnerability exposure
- Recommend specific Dockerfile improvements

### 4. Security Posture Score (Planned)

**Vision**: Single metric that captures container security posture.

**Score Components**:
- Vulnerability score (weighted by severity, fixability, layer)
- Configuration score (root user, secrets, healthcheck, etc.)
- Build quality score (layer count, size, optimization)
- Supply chain score (provenance, signatures, base image freshness)

---

## Implementation Roadmap

### Completed

- [x] Layer-aware vulnerability attribution
- [x] Image configuration extraction
- [x] ImageInfo wired to CEL policies
- [x] Container image diff command
- [x] OCI proxy with policy enforcement
- [x] CycloneDX/SPDX SBOM generation

### In Progress

- [ ] Base image detection improvements
- [ ] Build practice analysis

### Planned

- [ ] SLSA provenance verification
- [ ] Signature verification (cosign/notation)
- [ ] Security posture score
- [ ] Base image recommendation engine

---

## Competitive Analysis

| Feature | Deputy | Trivy | Grype | Snyk |
|---------|--------|-------|-------|------|
| Layer-aware vulns | Yes | Partial | No | Partial |
| Config in policies | Yes | No | No | Limited |
| Runtime enforcement | Yes (proxy) | No | No | Yes (limited) |
| Image diff | Yes | No | No | No |
| Base image tracking | Partial | No | No | Partial |
| Build analysis | Partial | No | No | No |
| Provenance verification | Planned | Partial | No | Partial |
| Policy language | CEL (powerful) | Rego | None | None |

---

## Conclusion

Deputy has strong container image security capabilities with unique differentiators:

1. **Layer-aware everything** - Vulns, packages, configs all track layers
2. **Policy-driven enforcement** - CEL policies at scan and proxy time
3. **Image diff** - Proper layer-aware image comparison
4. **Build intelligence** - Dockerfile analysis and recommendations

The roadmap focuses on supply chain provenance (SLSA, signatures) and security scoring to complete the enterprise feature set.
