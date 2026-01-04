# Container Image Implementation Plan

## Vision

Deputy becomes the go-to tool for container image dependency management, security, and compliance by providing:
1. **Semantic image diffing** - First-class `deputy diff` for container images
2. **Composable image analysis** - SBOM, vulnerabilities, licenses, and policies work together seamlessly
3. **Supply chain intelligence** - Base image tracking, provenance verification, and trust validation
4. **Extensible architecture** - Foundation for future capabilities (signing, VirusTotal, etc.)

---

## Phase 1: Foundation & Bug Fixes (Week 1-2)

### 1.1 Complete ImageInfo Wiring [DONE]
- [x] Wire `scan.Result.ImageInfo` to policy evaluation in `runScanPolicies()`
- [x] Add `image_info` to default CEL variable names
- [x] Update LSP completions for `image.config.*`, `image.metadata.*`, `vulnerability.layerDetails.*`

### 1.2 Remaining Bug Fixes

#### 1.2.1 Wire ImageInfo to OCI Proxy Policies
**File**: `internal/proxy/oci.go`

Currently, the OCI proxy handler only passes vulnerabilities to policies, not ImageInfo. Need to:
- Extract ImageInfo during proxy image scans
- Pass to policy evaluation payload

```go
// In scanImageForPolicy, capture ImageInfo from scan result
exec, err := h.scanner.ScanContainerImage(scanCtx, target, nil, scan.Options{})
// ...
if exec.Result.ImageInfo != nil {
    // Return ImageInfo along with vulnerabilities
}
```

#### 1.2.2 Add Container Image Entrypoints
**File**: `internal/policy/entrypoints.go`

Add new entrypoints for container-specific policy evaluation:

```go
const (
    // Existing...

    // Container image diff entrypoints
    EntrypointContainerDiffReport     = "container_diff_report"
    EntrypointContainerDiffChange     = "container_diff_change"
    EntrypointContainerDiffLayer      = "container_diff_layer"
    EntrypointContainerDiffVuln       = "container_diff_vulnerability"

    // Container image SBOM entrypoints
    EntrypointContainerSBOMReport     = "container_sbom_report"
    EntrypointContainerSBOMComponent  = "container_sbom_component"
)
```

### 1.3 SBOM Clarity for Container Images

#### 1.3.1 Explicit Container SBOM Command
**File**: `internal/cli/cmd/sbom.go`

Ensure `deputy sbom` works cleanly with container images:

```bash
# Current (works but not obvious)
deputy sbom docker://alpine:3.19

# Make explicit with documentation and examples
deputy sbom --format cyclonedx-json docker://myapp:latest
deputy sbom --format spdx-json oci://gcr.io/myproject/myapp@sha256:abc...
```

Document in AGENTS.md:
- Supported image schemes (`docker://`, `oci://`, `container://`, etc.)
- Layer-aware SBOM output
- License enrichment for container packages

#### 1.3.2 Container SBOM Metadata
Ensure container-specific metadata in SBOM output:
- Image digest
- Layer information for each component
- Base image reference (when detectable)
- Build timestamp

---

## Phase 2: Semantic Container Image Diff (Week 3-5)

### 2.1 Core Data Structures

**File**: `internal/compare/image_diff.go` (new)

```go
package compare

import (
    "github.com/picatz/deputy/internal/scan"
    "github.com/picatz/deputy/internal/vulnerability"
)

// ImageDiffResult represents the semantic difference between two container images.
type ImageDiffResult struct {
    BaseImage      ImageRef           `json:"baseImage"`
    TargetImage    ImageRef           `json:"targetImage"`
    PackageChanges []PackageChange    `json:"packageChanges"`
    ConfigChanges  *ConfigDiff        `json:"configChanges,omitempty"`
    LayerAnalysis  *LayerDiffAnalysis `json:"layerAnalysis,omitempty"`
    Vulnerabilities struct {
        Added    []VulnWithContext `json:"added"`
        Removed  []VulnWithContext `json:"removed"`
        Existing []VulnWithContext `json:"existing"`
    } `json:"vulnerabilities"`
}

// ImageRef identifies a container image.
type ImageRef struct {
    Registry   string `json:"registry"`
    Repository string `json:"repository"`
    Tag        string `json:"tag,omitempty"`
    Digest     string `json:"digest"`
    Display    string `json:"display"` // Human-readable reference
}

// PackageChange extends compare.Change with layer tracking.
type PackageChange struct {
    Change                        // Embedded: Name, OldName, TargetVersion, BaseVersion, ChangeType, Ecosystem, IsDirect
    BaseLayerDetails   *LayerInfo `json:"baseLayerDetails,omitempty"`
    TargetLayerDetails *LayerInfo `json:"targetLayerDetails,omitempty"`
}

// LayerInfo captures layer context for a package.
type LayerInfo struct {
    Index       int    `json:"index"`
    DiffID      string `json:"diffId"`
    ChainID     string `json:"chainId"`
    Command     string `json:"command"`
    InBaseImage bool   `json:"inBaseImage"`
}

// ConfigDiff captures changes in image configuration.
type ConfigDiff struct {
    UserChanged       *StringChange   `json:"userChanged,omitempty"`
    EntrypointChanged *SliceChange    `json:"entrypointChanged,omitempty"`
    CmdChanged        *SliceChange    `json:"cmdChanged,omitempty"`
    EnvAdded          []string        `json:"envAdded,omitempty"`
    EnvRemoved        []string        `json:"envRemoved,omitempty"`
    EnvChanged        []EnvChange     `json:"envChanged,omitempty"`
    PortsAdded        []string        `json:"portsAdded,omitempty"`
    PortsRemoved      []string        `json:"portsRemoved,omitempty"`
    VolumesAdded      []string        `json:"volumesAdded,omitempty"`
    VolumesRemoved    []string        `json:"volumesRemoved,omitempty"`
    LabelsAdded       map[string]string `json:"labelsAdded,omitempty"`
    LabelsRemoved     []string          `json:"labelsRemoved,omitempty"`
    LabelsChanged     map[string]StringChange `json:"labelsChanged,omitempty"`
    HealthcheckChanged bool            `json:"healthcheckChanged,omitempty"`
}

// LayerDiffAnalysis provides layer-level comparison.
type LayerDiffAnalysis struct {
    BaseLayerCount   int           `json:"baseLayerCount"`
    TargetLayerCount int           `json:"targetLayerCount"`
    CommonLayers     int           `json:"commonLayers"`     // Layers with matching chainId
    AddedLayers      []LayerSummary `json:"addedLayers"`
    RemovedLayers    []LayerSummary `json:"removedLayers"`
    ModifiedLayers   []LayerSummary `json:"modifiedLayers"` // Same position, different content
}

// VulnWithContext adds diff context to a vulnerability.
type VulnWithContext struct {
    vulnerability.Finding
    ChangeContext string `json:"changeContext"` // "added", "removed", "existing"
    InBaseImage   bool   `json:"inBaseImage,omitempty"`
    InTargetImage bool   `json:"inTargetImage,omitempty"`
}
```

### 2.2 Image Diff Service

**File**: `internal/scan/image_diff.go` (new)

```go
package scan

import (
    "context"
    "github.com/picatz/deputy/internal/compare"
)

// ImageDiffOptions configures image diff behavior.
type ImageDiffOptions struct {
    IncludeVulnScan   bool   // Run vulnerability scanning on both images
    IncludeConfigDiff bool   // Compare image configurations
    IncludeLayerDiff  bool   // Analyze layer changes
    BaseImageHint     string // Optional: explicit base image reference for better detection
}

// DiffContainerImages compares two container images semantically.
func (s *Service) DiffContainerImages(ctx context.Context, baseRef, targetRef string, opts ImageDiffOptions) (*compare.ImageDiffResult, error) {
    // 1. Load both images
    baseData, err := s.loadImage(ctx, baseRef)
    if err != nil {
        return nil, fmt.Errorf("load base image %q: %w", baseRef, err)
    }
    targetData, err := s.loadImage(ctx, targetRef)
    if err != nil {
        return nil, fmt.Errorf("load target image %q: %w", targetRef, err)
    }

    // 2. Extract inventories with layer info
    baseInv, err := s.scanImageInventory(ctx, baseData)
    targetInv, err := s.scanImageInventory(ctx, targetData)

    // 3. Compare packages with layer tracking
    pkgChanges := comparePackagesWithLayers(baseInv, targetInv)

    // 4. Compare configurations (if enabled)
    var configDiff *compare.ConfigDiff
    if opts.IncludeConfigDiff {
        configDiff = diffImageConfigs(baseData.Config, targetData.Config)
    }

    // 5. Analyze layers (if enabled)
    var layerAnalysis *compare.LayerDiffAnalysis
    if opts.IncludeLayerDiff {
        layerAnalysis = analyzeLayerChanges(baseData, targetData)
    }

    // 6. Scan for vulnerabilities (if enabled)
    var vulnDiff VulnerabilityDiff
    if opts.IncludeVulnScan {
        vulnDiff = diffVulnerabilities(ctx, baseInv, targetInv)
    }

    return &compare.ImageDiffResult{
        BaseImage:       imageRefFromData(baseData),
        TargetImage:     imageRefFromData(targetData),
        PackageChanges:  pkgChanges,
        ConfigChanges:   configDiff,
        LayerAnalysis:   layerAnalysis,
        Vulnerabilities: vulnDiff,
    }, nil
}
```

### 2.3 CLI Command

**File**: `internal/cli/cmd/diff_image.go` (new)

```go
// AddImageDiffCommand adds container image diff support to the diff command.
// Usage:
//   deputy diff docker://myapp:v1.0 docker://myapp:v2.0
//   deputy diff --base alpine:3.19 docker://myapp:latest
//   deputy diff gcr.io/prod/app:stable gcr.io/staging/app:latest

func AddImageDiffCommand(diffCmd *cobra.Command, service *scan.Service) {
    var (
        skipVulnScan   bool
        skipConfigDiff bool
        skipLayerDiff  bool
        baseImageHint  string
        policyPaths    []string
        format         string
    )

    // Detect if arguments are image references
    diffCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
        if len(args) >= 1 && isImageReference(args[0]) {
            // Route to image diff logic
            return runImageDiff(cmd, args, service, /* flags */)
        }
        // Fall through to git diff
        return nil
    }
}

func isImageReference(ref string) bool {
    schemes := []string{"docker://", "oci://", "container://", "docker-daemon://", "tarball://", "oci-archive://", "oci-layout://"}
    for _, s := range schemes {
        if strings.HasPrefix(ref, s) {
            return true
        }
    }
    // Also detect registry references: gcr.io/*, docker.io/*, etc.
    if strings.Contains(ref, "/") && (strings.Contains(ref, ":") || strings.Contains(ref, "@")) {
        return true
    }
    return false
}
```

### 2.4 Policy Integration

**File**: Update `internal/cli/cmd/diff_image.go`

```go
func runImageDiffPolicies(ctx context.Context, policyPaths []string, result *compare.ImageDiffResult) ([]policy.Action, error) {
    var actions []policy.Action

    // 1. Evaluate container_diff_report
    reportPayload := buildImageDiffReportPayload(result)
    reportActions, err := evaluatePoliciesForCommand(ctx, policyPaths, reportPayload, "diff", "container_diff_report", os.Stderr)
    actions = append(actions, reportActions...)

    // 2. Evaluate container_diff_change for each package change
    for _, change := range result.PackageChanges {
        changePayload := buildImageDiffChangePayload(result, change)
        changeActions, err := evaluatePoliciesForCommand(ctx, policyPaths, changePayload, "diff", "container_diff_change", os.Stderr)
        actions = append(actions, changeActions...)
    }

    // 3. Evaluate container_diff_vulnerability for each vuln
    for _, vuln := range result.Vulnerabilities.Added {
        vulnPayload := buildImageDiffVulnPayload(result, vuln, "added")
        vulnActions, err := evaluatePoliciesForCommand(ctx, policyPaths, vulnPayload, "diff", "container_diff_vulnerability", os.Stderr)
        actions = append(actions, vulnActions...)
    }

    return actions, nil
}
```

### 2.5 Example Policies

**File**: `policy/examples/container-diff.yaml`

```yaml
policies:
  # Block if critical vulnerabilities were added
  - name: block-new-critical-vulns
    entrypoints: [container_diff_vulnerability]
    rules:
      - action: deny
        when: |
          vulnerability.changeContext == 'added' &&
          vulnerability.severity == 'CRITICAL'
        reason: "Image update introduces new critical vulnerability"

  # Warn on unexpected package additions in app layers
  - name: unexpected-package-additions
    entrypoints: [container_diff_change]
    rules:
      - action: warn
        when: |
          change.changeType == 'added' &&
          has(change.targetLayerDetails) &&
          !change.targetLayerDetails.inBaseImage &&
          !change.targetLayerDetails.command.matches('(npm|pip|apt-get|apk) install')
        reason: "Package added outside standard package manager"

  # Alert on configuration drift
  - name: config-drift-detection
    entrypoints: [container_diff_report]
    rules:
      - action: warn
        when: |
          has(configChanges) && (
            configChanges.userChanged != null ||
            size(configChanges.envAdded) > 0 ||
            configChanges.entrypointChanged != null
          )
        reason: "Image configuration changed - review for security impact"

  # Block if base image layers changed unexpectedly
  - name: base-image-change-detection
    entrypoints: [container_diff_report]
    rules:
      - action: warn
        when: |
          has(layerAnalysis) &&
          layerAnalysis.commonLayers < layerAnalysis.baseLayerCount
        reason: "Base image layers appear to have changed"
```

---

## Phase 3: Base Image Intelligence (Week 6-7)

### 3.1 Base Image Detection

**File**: `internal/scan/base_image.go` (new)

```go
package scan

// BaseImageInfo captures detected base image information.
type BaseImageInfo struct {
    Detected       bool     `json:"detected"`
    Reference      string   `json:"reference,omitempty"`      // e.g., "alpine:3.19"
    Digest         string   `json:"digest,omitempty"`         // SHA256 digest
    FirstLayerIdx  int      `json:"firstLayerIdx"`            // Where base ends, app begins
    LastLayerIdx   int      `json:"lastLayerIdx"`             // Last base layer index
    Confidence     float64  `json:"confidence"`               // 0.0-1.0 detection confidence
    DetectionMethod string  `json:"detectionMethod"`          // "label", "history", "heuristic"
}

// DetectBaseImage attempts to identify the base image used.
func DetectBaseImage(img v1.Image, history []ImageHistoryEntry) (*BaseImageInfo, error) {
    info := &BaseImageInfo{Detected: false}

    // Method 1: Check labels (most reliable)
    cfg, _ := img.ConfigFile()
    if cfg != nil && cfg.Config.Labels != nil {
        if baseRef := cfg.Config.Labels["org.opencontainers.image.base.name"]; baseRef != "" {
            info.Detected = true
            info.Reference = baseRef
            info.Digest = cfg.Config.Labels["org.opencontainers.image.base.digest"]
            info.DetectionMethod = "label"
            info.Confidence = 1.0
            // Find layer boundary
            info.FirstLayerIdx, info.LastLayerIdx = findBaseLayerBoundary(history, baseRef)
            return info, nil
        }
    }

    // Method 2: Analyze history for FROM instruction patterns
    baseInfo := detectFromHistory(history)
    if baseInfo != nil {
        return baseInfo, nil
    }

    // Method 3: Heuristic based on common base image patterns
    return detectFromHeuristics(img, history)
}

// detectFromHistory looks for FROM patterns in layer history.
func detectFromHistory(history []ImageHistoryEntry) *BaseImageInfo {
    // Look for patterns like:
    // - Empty layers with comments containing base image reference
    // - Known base image layer signatures
    // ...
}
```

### 3.2 Base Image Recommendations

**File**: `internal/analysis/base_image_advisor.go` (new)

```go
package analysis

// BaseImageRecommendation suggests a base image update.
type BaseImageRecommendation struct {
    CurrentBase     string `json:"currentBase"`
    RecommendedBase string `json:"recommendedBase"`
    Reason          string `json:"reason"`
    VulnReduction   int    `json:"vulnReduction"`   // Estimated vuln count reduction
    SizeChange      int64  `json:"sizeChange"`      // Size delta in bytes
    Breaking        bool   `json:"breaking"`        // Likely breaking change?
}

// AnalyzeBaseImageOptions returns recommendations for base image updates.
func AnalyzeBaseImageOptions(ctx context.Context, currentBase string, vulns []vulnerability.Finding) ([]BaseImageRecommendation, error) {
    // Query known base image vulnerability data
    // Compare with alternatives (e.g., alpine -> distroless)
    // Generate recommendations
}
```

### 3.3 Policy Variables for Base Image

Update `buildScanImagePayload` to include base image info:

```go
if result.ImageInfo != nil {
    imageInfo := result.ImageInfo.ToMap()
    // Add base image detection results
    if baseInfo := result.BaseImageInfo; baseInfo != nil {
        imageInfo["base_image"] = map[string]any{
            "detected":   baseInfo.Detected,
            "reference":  baseInfo.Reference,
            "digest":     baseInfo.Digest,
            "confidence": baseInfo.Confidence,
        }
    }
}
```

### 3.4 Base Image Policies

**File**: `policy/examples/base-image-policies.yaml`

```yaml
policies:
  # Require approved base images
  - name: approved-base-images
    entrypoints: [scan_report, oci_artifact_request]
    vars:
      approvedBases:
        - "docker.io/library/alpine"
        - "gcr.io/distroless"
        - "docker.io/library/debian"
    rules:
      - action: deny
        when: |
          has(image.base_image) &&
          image.base_image.detected &&
          !approvedBases.exists(b, image.base_image.reference.startsWith(b))
        reason: "Base image not in approved list"

  # Warn on stale base images
  - name: base-image-freshness
    entrypoints: [scan_report]
    rules:
      - action: warn
        when: |
          has(image.history) &&
          image.history.size() > 0 &&
          age(image.history[0].created) > duration('90d')
        reason: "Base image layers are older than 90 days"

  # Block undetectable base images in production
  - name: require-base-image-label
    entrypoints: [oci_artifact_request]
    vars:
      productionRegistries: ["gcr.io/prod", "docker.io/mycompany"]
    rules:
      - action: warn
        when: |
          productionRegistries.exists(r, image.registry.startsWith(r)) &&
          (!has(image.base_image) || !image.base_image.detected)
        reason: "Production images should have base image labels for traceability"
```

---

## Phase 4: Supply Chain Provenance (Week 8-10)

### 4.1 Provenance Data Structures

**File**: `internal/provenance/types.go` (new)

```go
package provenance

// ImageProvenance captures supply chain attestation data.
type ImageProvenance struct {
    // SLSA Provenance
    SLSA *SLSAProvenance `json:"slsa,omitempty"`

    // Signatures
    Signatures []ImageSignature `json:"signatures,omitempty"`

    // Build metadata
    Build *BuildInfo `json:"build,omitempty"`

    // Source code link
    Source *SourceInfo `json:"source,omitempty"`
}

type SLSAProvenance struct {
    BuilderID      string    `json:"builderId"`
    BuildType      string    `json:"buildType"`
    Invocation     any       `json:"invocation,omitempty"`
    Materials      []Material `json:"materials,omitempty"`
    Verified       bool      `json:"verified"`
    VerificationError string `json:"verificationError,omitempty"`
}

type ImageSignature struct {
    KeyID       string `json:"keyId"`
    Algorithm   string `json:"algorithm"`
    Verified    bool   `json:"verified"`
    SignedBy    string `json:"signedBy,omitempty"` // DN or email
    Timestamp   int64  `json:"timestamp,omitempty"`
    VerificationError string `json:"verificationError,omitempty"`
}

type BuildInfo struct {
    Builder     string `json:"builder"`      // e.g., "github-actions", "jenkins"
    BuildID     string `json:"buildId"`
    BuildURL    string `json:"buildUrl,omitempty"`
    Timestamp   int64  `json:"timestamp"`
    Reproducible bool  `json:"reproducible"`
}

type SourceInfo struct {
    Repository string `json:"repository"`
    Commit     string `json:"commit"`
    Branch     string `json:"branch,omitempty"`
    Tag        string `json:"tag,omitempty"`
}
```

### 4.2 Provenance Verification

**File**: `internal/provenance/verify.go` (new)

```go
package provenance

import (
    "context"
    "github.com/sigstore/cosign/v2/pkg/cosign"
)

// VerifyOptions configures provenance verification.
type VerifyOptions struct {
    // Signature verification
    RequireSignature bool
    TrustedKeys      []string // PEM-encoded public keys or key references
    KeylessVerify    bool     // Use Sigstore keyless verification

    // SLSA verification
    RequireSLSA      bool
    MinSLSALevel     int      // 1, 2, 3, or 4
    TrustedBuilders  []string // Allowed builder IDs

    // Certificate verification
    CertIdentity     string   // Expected certificate identity
    CertOIDCIssuer   string   // Expected OIDC issuer
}

// Verify checks image provenance against requirements.
func Verify(ctx context.Context, imageRef string, opts VerifyOptions) (*VerificationResult, error) {
    result := &VerificationResult{ImageRef: imageRef}

    // 1. Fetch attestations from registry
    attestations, err := fetchAttestations(ctx, imageRef)
    if err != nil {
        return nil, fmt.Errorf("fetch attestations: %w", err)
    }

    // 2. Verify signatures if required
    if opts.RequireSignature {
        sigResult, err := verifySignatures(ctx, imageRef, opts)
        result.Signatures = sigResult
        if err != nil {
            result.Errors = append(result.Errors, err.Error())
        }
    }

    // 3. Verify SLSA provenance if required
    if opts.RequireSLSA {
        slsaResult, err := verifySLSA(ctx, attestations, opts)
        result.SLSA = slsaResult
        if err != nil {
            result.Errors = append(result.Errors, err.Error())
        }
    }

    result.Verified = len(result.Errors) == 0
    return result, nil
}
```

### 4.3 Policy Integration for Provenance

```yaml
policies:
  # Require signed images
  - name: require-signatures
    entrypoints: [oci_artifact_request]
    rules:
      - action: deny
        when: |
          !has(image.provenance) ||
          !has(image.provenance.signatures) ||
          !image.provenance.signatures.exists(s, s.verified)
        reason: "Image must be signed"

  # Require SLSA Level 3+ for production
  - name: require-slsa-l3
    entrypoints: [oci_artifact_request]
    vars:
      productionRepos: ["gcr.io/prod"]
    rules:
      - action: deny
        when: |
          productionRepos.exists(r, image.repository.startsWith(r)) &&
          (!has(image.provenance.slsa) ||
           !image.provenance.slsa.verified ||
           image.provenance.slsa.level < 3)
        reason: "Production images require SLSA Level 3+ provenance"

  # Require specific builders
  - name: trusted-builders
    entrypoints: [oci_artifact_request]
    vars:
      trustedBuilders:
        - "https://github.com/slsa-framework/slsa-github-generator"
        - "https://cloudbuild.googleapis.com/GoogleHostedWorker"
    rules:
      - action: deny
        when: |
          has(image.provenance.slsa) &&
          !trustedBuilders.exists(b, image.provenance.slsa.builderId == b)
        reason: "Image must be built by trusted builder"
```

---

## Phase 5: Future Extensibility (Week 11+)

### 5.1 VirusTotal Integration (Future)

**File**: `internal/analysis/virustotal/client.go` (future)

```go
package virustotal

// ScanResult represents a VirusTotal scan result for an image layer or binary.
type ScanResult struct {
    Resource    string            `json:"resource"`
    SHA256      string            `json:"sha256"`
    Positives   int               `json:"positives"`
    Total       int               `json:"total"`
    ScanDate    time.Time         `json:"scanDate"`
    Detections  map[string]string `json:"detections,omitempty"`
}

// ScanImageLayers submits image layer contents to VirusTotal for analysis.
func ScanImageLayers(ctx context.Context, img v1.Image, apiKey string) ([]ScanResult, error) {
    // For each layer, compute hash and check VirusTotal
    // Cache results by layer digest
}
```

### 5.2 SBOM Signing (Future)

```go
// SignSBOM signs an SBOM with the provided key.
func SignSBOM(sbom *protobom.Document, keyPath string) (*SignedSBOM, error) {
    // Generate signature over SBOM content
    // Support multiple signature formats (cosign, GPG, etc.)
}

// VerifySBOMSignature verifies an SBOM signature.
func VerifySBOMSignature(signed *SignedSBOM, publicKey string) error {
    // Verify signature matches content
}
```

### 5.3 Image Hash Verification

```go
// VerifyImageIntegrity checks that image content matches expected digests.
func VerifyImageIntegrity(ctx context.Context, imageRef string, expected ExpectedDigests) (*IntegrityResult, error) {
    // Pull image and verify:
    // - Manifest digest
    // - Config digest
    // - Layer digests
    // - Optional: content hashes for specific files
}
```

---

## Architecture Principles

### Composability
All features should work together naturally:
```bash
# SBOM + vulnerabilities + policies
deputy sbom docker://myapp:latest --vulns --policy policy/container.yaml

# Diff + SBOM delta + policies
deputy diff docker://myapp:v1 docker://myapp:v2 --sbom-delta --policy policy/diff.yaml

# Scan + provenance verification
deputy scan docker://myapp:latest --verify-provenance --slsa-level 3
```

### Consistent Data Model
All container operations share the same data structures:
- `ImageRef` for image identification
- `ImageInfo` for config/metadata
- `LayerDetails` for layer context
- `Provenance` for supply chain data

### Policy-First Design
Every feature exposes data to the CEL policy engine:
- New data → new policy variables
- New operations → new entrypoints
- Consistent naming: `container_*` for container-specific entrypoints

### Extensible Foundation
Architecture supports future capabilities:
- Plugin interface for new verification methods
- Webhook support for external analysis
- Cache infrastructure for performance

---

## Testing Strategy

### Unit Tests
- `compare/image_diff_test.go` - Package comparison with layers
- `scan/base_image_test.go` - Base image detection
- `provenance/verify_test.go` - Signature/SLSA verification

### Integration Tests
- `internal/cli/cmd/diff_image_test.go` - End-to-end image diff
- `internal/proxy/oci_policy_test.go` - Proxy policy evaluation with ImageInfo

### Example-Based Tests
- Policy examples in `policy/examples/` serve as documentation AND tests
- Each example policy should have a corresponding test case

---

## Documentation Updates

### AGENTS.md
- Add container image diff section
- Document `container_diff_*` entrypoints
- Add base image policy examples
- Document provenance variables

### docs/commands/
- `diff.md` - Add image diff examples
- `sbom.md` - Clarify container image SBOM generation
- `scan.md` - Document ImageInfo availability

### docs/guides/
- `container-security.md` - Comprehensive container security guide
- `supply-chain.md` - Provenance and signing guide

---

## Migration Path

### Backward Compatibility
- Existing `deputy scan docker://...` continues to work
- Existing policies using `image.*` continue to work (now with more data)
- `deputy diff` auto-detects image references vs git refs

### Deprecations
- None required - all changes are additive

### Feature Flags (if needed)
- `--experimental-image-diff` for early access
- `--verify-provenance` opt-in for supply chain verification
