# Deputy Container Image Strategy: World-Class Vision

## Executive Summary

Deputy has strong foundational infrastructure for container image scanning, but to achieve market differentiation and become truly world-class, we need to address critical gaps and build unique capabilities that competitors don't offer. This document outlines the strategic vision.

## Current State Assessment

### What We Have (Strengths)

1. **Layer-Aware Vulnerability Attribution** - Each vulnerability tagged with `LayerDetails` (index, diffId, chainId, command, inBaseImage)
2. **Rich Image Configuration Extraction** - User, env, sensitive_env detection, entrypoint, cmd, ports, volumes, labels, healthcheck, history
3. **Runtime Proxy Enforcement** - Policy evaluation BEFORE image pull (unique positioning)
4. **Flexible CEL Policy Engine** - Powerful expression language with custom helpers
5. **SBOM Generation** - CycloneDX/SPDX with layer metadata

### Critical Gap: ImageInfo Not Wired to Policies

**Problem**: `scan.Result.ImageInfo` is extracted but NOT passed to policy evaluation.

The `buildScanImagePayload()` function only uses target provenance (registry, repository, tag, digest). The extracted config, metadata, and history are discarded before reaching CEL.

**Impact**: Policies cannot currently access:
- `image.config.user`, `image.config.is_root`
- `image.config.sensitive_env`
- `image.metadata.layer_count`, `image.metadata.size`
- `image.history[].created_by`

**Fix Required**: Wire `scan.Result.ImageInfo.ToMap()` into the policy input map.

---

## Strategic Differentiation Opportunities

### 1. Container Image Diff (The Big One)

**Current State**: `deputy diff` only works with Git repositories.

**Vision**: First-class container image diff capability.

```bash
# Compare two image versions
deputy diff docker://myapp:v1.0 docker://myapp:v2.0

# Compare image to its base
deputy diff --base alpine:3.19 docker://myapp:latest

# Compare across registries
deputy diff gcr.io/prod/myapp:stable gcr.io/staging/myapp:latest
```

**Unique Value Proposition**:
- Layer-by-layer package comparison (not just "what changed" but "in which layer")
- Base image drift detection (your base image got new vulns)
- Vulnerability delta with remediation guidance
- Configuration drift detection (env vars added, user changed)

**Data Model Extension**:

```go
type Change struct {
    // Existing fields...
    Name, OldName, TargetVersion, BaseVersion string
    ChangeType ChangeType
    Ecosystem string
    IsDirect bool

    // NEW: Layer tracking
    BaseLayerDetails    *LayerDetails  // where pkg was in base image
    TargetLayerDetails  *LayerDetails  // where pkg is in target image
}

type ImageDiffReport struct {
    BaseImage       ImageRef
    TargetImage     ImageRef
    PackageChanges  []Change
    ConfigChanges   ImageConfigDiff
    Vulnerabilities []Vulnerability
    LayerAnalysis   LayerDiffAnalysis
}
```

**Policy Entrypoints**:
- `container_diff_report` - Full diff with all metadata
- `container_diff_change` - Per-package change with layer info
- `container_diff_layer` - Per-layer analysis
- `container_diff_vulnerability` - Per-vuln with layer context

**Example Policies**:

```yaml
# Block if base image introduced new critical vulns
- name: base-image-regression
  entrypoints: [container_diff_vulnerability]
  rules:
    - action: deny
      when: |
        vulnerability.severity == 'CRITICAL' &&
        has(vulnerability.layerDetails) &&
        vulnerability.layerDetails.inBaseImage &&
        change.type == 'added'  # New vuln, not present in previous version
      reason: "Base image update introduced new critical vulnerability"

# Detect unexpected package additions in app layers
- name: unexpected-packages
  entrypoints: [container_diff_change]
  rules:
    - action: warn
      when: |
        change.type == 'added' &&
        has(change.targetLayerDetails) &&
        !change.targetLayerDetails.inBaseImage &&
        !change.targetLayerDetails.command.contains('npm install') &&
        !change.targetLayerDetails.command.contains('pip install')
      reason: "Package added outside of expected package manager commands"
```

### 2. Base Image Intelligence

**Vision**: Deputy knows which base images are best for security, and can recommend upgrades.

**Capabilities**:
- Track vulnerability density across popular base images
- Alert when chosen base image falls behind alternatives
- Recommend specific base image updates with impact analysis
- Detect when base image is EOL or deprecated

**Data Requirements**:
- Base image detection heuristics (already partial via `inBaseImage`)
- Base image genealogy tracking (FROM instruction chain)
- Base image vulnerability database (aggregate scans)

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

### 3. Supply Chain Provenance

**Vision**: Deputy validates and enforces supply chain attestations.

**Capabilities**:
- Verify SLSA provenance attestations
- Validate image signatures (cosign, notation)
- Enforce required OCI annotations
- Track builder identity and build timestamp

**Policy Examples**:

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

### 4. Build Practice Analysis

**Vision**: Deputy analyzes Dockerfile commands and recommends improvements.

**Capabilities**:
- Detect anti-patterns (unpinned package versions, curl | bash, etc.)
- Score build hygiene (layer consolidation, cache efficiency)
- Track how build practices correlate with vulnerability exposure
- Recommend specific Dockerfile improvements

**Analysis Output**:

```yaml
build_analysis:
  score: 72/100
  issues:
    - severity: high
      layer: 3
      command: "RUN apt-get update && apt-get install -y curl"
      issue: "Package versions not pinned"
      recommendation: "Use apt-get install -y curl=7.88.1-10+deb12u5"
    - severity: medium
      layer: 5
      command: "RUN npm install"
      issue: "npm install without --production"
      recommendation: "Use npm ci --production for smaller image"
  recommendations:
    - "Combine RUN commands on layers 3-5 to reduce layer count"
    - "Use multi-stage build to exclude build dependencies"
```

### 5. Runtime Security Posture Score

**Vision**: Single metric that captures container security posture.

**Score Components**:
- Vulnerability score (weighted by severity, fixability, layer)
- Configuration score (root user, secrets, healthcheck, etc.)
- Build quality score (layer count, size, optimization)
- Supply chain score (provenance, signatures, base image freshness)

**Policy Integration**:

```yaml
# Block images below security threshold
- name: minimum-security-score
  entrypoints: [oci_artifact_request]
  rules:
    - action: deny
      when: |
        security_score(image) < 70
      reason: "Image security score below minimum threshold"
```

---

## Implementation Priorities

### Phase 1: Foundation (Immediate)

1. **Wire ImageInfo to policies** - Critical gap, enables all config-based policies
2. **Complete layer details propagation** - Ensure all scan paths include layer metadata
3. **Add container_diff entrypoints** - Policy hooks for future diff capability

### Phase 2: Container Diff (High Impact)

4. **Implement image diff command** - `deputy diff <image1> <image2>`
5. **Layer-aware comparison** - Track package migration across layers
6. **Config diff visualization** - Show what changed in image config
7. **Vulnerability delta analysis** - New vulns vs. fixed vulns

### Phase 3: Intelligence (Differentiation)

8. **Base image detection** - Reliable FROM chain analysis
9. **Base image recommendations** - "Switch to X to reduce vulns by Y"
10. **Build practice scoring** - Dockerfile analysis and recommendations
11. **Security posture score** - Unified metric

### Phase 4: Supply Chain (Enterprise)

12. **SLSA provenance verification** - Attestation validation
13. **Signature verification** - cosign/notation integration
14. **Supply chain graph** - Image dependency visualization

---

## Competitive Analysis

| Feature | Deputy (Current) | Deputy (Vision) | Trivy | Grype | Snyk |
|---------|-----------------|-----------------|-------|-------|------|
| Layer-aware vulns | Yes | Yes | Partial | No | Partial |
| Config analysis | Extracted, not wired | Full policy access | No | No | Limited |
| Runtime enforcement | Yes (proxy) | Yes | No | No | Yes (limited) |
| Image diff | No | Full layer diff | No | No | No |
| Base image tracking | Partial | Full genealogy | No | No | Partial |
| Build analysis | No | Full scoring | No | No | No |
| Provenance verification | No | Full SLSA | Partial | No | Partial |
| Policy language | CEL (powerful) | CEL (powerful) | Rego | None | None |

---

## Success Metrics

1. **Adoption**: Container image scans per month
2. **Policy usage**: % of scans with custom policies
3. **Diff adoption**: Container diff commands per month
4. **Proxy enforcement**: Images blocked/allowed ratio
5. **User satisfaction**: NPS from container image users

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Performance at scale | Aggressive caching, parallel layer scanning |
| Registry compatibility | Test against major registries (Docker Hub, GCR, ECR, ACR, GHCR) |
| Policy complexity | Good documentation, policy examples, LSP support |
| Attestation fragmentation | Support multiple formats (SLSA, in-toto, sigstore) |

---

## Conclusion

Deputy has the foundational architecture to become the most powerful container image security tool in the market. The key differentiators are:

1. **Layer-aware everything** - Not just vulns, but packages, configs, and diffs
2. **Policy-driven enforcement** - CEL policies at scan and proxy time
3. **Image diff** - No competitor offers proper layer-aware image comparison
4. **Build intelligence** - Actionable recommendations, not just findings

The immediate priority is completing the ImageInfo wiring so policies can access the rich data we already extract. Then, container image diff becomes the flagship feature that sets Deputy apart.
