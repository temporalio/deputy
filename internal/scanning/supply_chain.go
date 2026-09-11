package scanning

import (
	"context"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/forge"
	"github.com/temporalio/deputy/internal/inventory/plugins/docker/dockerfilex"
	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Supply chain advisory IDs for non-CVE findings produced by Deputy.
const (
	// AdvisoryUnpinnedAction is reported when a GitHub Actions reference uses
	// a mutable tag (e.g., @v4) instead of an immutable commit SHA. Mutable
	// tags can be force-pushed to point at malicious commits.
	AdvisoryUnpinnedAction = "DEPUTY-SC-UNPINNED-ACTION"

	// AdvisoryUnpinnedImage is reported when a container image reference uses
	// a mutable tag (e.g., :latest, :3.19) instead of a sha256 digest. Image
	// tags can be re-pushed to point at different content.
	AdvisoryUnpinnedImage = "DEPUTY-SC-UNPINNED-IMAGE"
)

// supplyChainAdvisories returns the static advisory definitions for
// Deputy's supply-chain findings. Callers should merge these into their
// advisory map when supply-chain findings are present.
func supplyChainAdvisories() map[string]*vulnerabilityv1.Advisory {
	return map[string]*vulnerabilityv1.Advisory{
		AdvisoryUnpinnedAction: {
			Id:      AdvisoryUnpinnedAction,
			Summary: "GitHub Actions reference uses mutable tag instead of commit SHA",
			Details: "This GitHub Actions dependency is referenced by a mutable tag (e.g., @v4) " +
				"rather than an immutable commit SHA. An attacker who gains write access to the " +
				"action's repository can force-push the tag to a malicious commit, compromising " +
				"all workflows that use it. Pin to a commit SHA with: deputy pin",
			Severity: &vulnerabilityv1.Severity{
				Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CUSTOM,
				Raw:   "medium",
			},
			// The remediation is an action (running a command), not a version
			// upgrade, so it lives in DatabaseSpecific["remediation"] and not in
			// FixedVersions (which is reserved for semver upgrade targets).
			Cwes: []string{"CWE-829"},
			DatabaseSpecific: map[string]string{
				"type":        "supply-chain",
				"remediation": "deputy pin",
			},
		},
		AdvisoryUnpinnedImage: {
			Id:      AdvisoryUnpinnedImage,
			Summary: "Container image uses mutable tag instead of sha256 digest",
			Details: "This container image is referenced by a mutable tag (e.g., :latest, :3.19) " +
				"rather than an immutable sha256 digest. Image tags can be re-pushed to point " +
				"at different content, enabling supply chain attacks. Pin to a digest with: " +
				"deputy pin --ecosystems container-image",
			Severity: &vulnerabilityv1.Severity{
				Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CUSTOM,
				Raw:   "medium",
			},
			// The remediation is an action (running a command), not a version
			// upgrade, so it lives in DatabaseSpecific["remediation"] and not in
			// FixedVersions (which is reserved for semver upgrade targets).
			Cwes: []string{"CWE-829"},
			DatabaseSpecific: map[string]string{
				"type":        "supply-chain",
				"remediation": "deputy pin --ecosystems container-image",
			},
		},
	}
}

// checkSupplyChain inspects discovered packages for supply-chain risks
// that are not covered by CVE/advisory databases. Currently checks:
//
//   - Unpinned GitHub Actions references (mutable tag instead of SHA)
//   - Unpinned container images (mutable tag instead of sha256 digest)
//
// Returns additional findings and advisories to merge with vulnerability results.
func checkSupplyChain(_ context.Context, pkgs []*extractor.Package, direct map[string]bool, selfRepo string) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory) {
	var findings []vulnerability.Finding
	usedAdvisories := map[string]bool{}

	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		var advisoryID string
		var ecosystem string

		switch {
		case purlx.IsGitHubActionsType(pkg.PURLType):
			// Unpinned GitHub Actions reference.
			if (pin.Ref{Version: pkg.Version}).IsSHAPinned() {
				continue
			}
			// Skip references that use workflow expression syntax
			// (e.g., uses: foo/bar@${{ env.REF }}). These cannot be statically
			// pinned to a commit SHA, so `deputy pin` skips them too. Reporting
			// them here would recommend a fix that provably can't be applied.
			if strings.Contains(pkg.Version, "${{") {
				continue
			}
			// Skip self-references: a repository invoking its own actions or
			// reusable workflows (same owner/repo as the scan target) cannot be
			// pinned to a commit SHA without a chicken-and-egg problem, and an
			// attacker who can move the ref already controls the repository, so
			// pinning adds no protection. Flagging these is noise.
			if isSelfReference(pkg.Name, selfRepo) {
				continue
			}
			advisoryID = AdvisoryUnpinnedAction
			ecosystem = "GitHub Actions"

		case isContainerImageType(pkg.PURLType):
			// Unpinned container image.
			if strings.Contains(pkg.Version, "sha256:") {
				continue
			}
			// Skip images whose tag comes from a build-arg expression
			// (e.g., FROM alpine:${ALPINE_TAG}). ARG substitution flattens the
			// tag to "latest", but the FROM line can't be statically pinned to a
			// digest, so `deputy pin` skips it. Reporting it here would loop the
			// user back to a fix that can't be applied.
			if isExpressionImageRef(pkg) {
				continue
			}
			advisoryID = AdvisoryUnpinnedImage
			ecosystem = "Docker"

		default:
			continue
		}

		pu := pkg.PURL()
		var purlStr string
		if pu != nil {
			purlStr = pu.String()
		}

		isDirect := false
		if direct != nil && pu != nil {
			isDirect = direct[purlStr]
		}

		locs := dependency.PackagePaths(pkg)

		findings = append(findings, vulnerability.Finding{
			AdvisoryID: advisoryID,
			Dependency: dependency.ID{
				Name:      pkg.Name,
				Ecosystem: ecosystem,
				PURL:      purlStr,
			},
			Version:   pkg.Version,
			Direct:    isDirect,
			Locations: locs,
			Affected:  true,
		})
		usedAdvisories[advisoryID] = true
	}

	if len(findings) == 0 {
		return nil, nil
	}

	// Only return advisories that have findings.
	allAdvisories := supplyChainAdvisories()
	result := make(map[string]*vulnerabilityv1.Advisory, len(usedAdvisories))
	for id := range usedAdvisories {
		result[id] = allAdvisories[id]
	}
	return findings, result
}

// isSelfReference reports whether a GitHub Actions package name refers to the
// same repository being scanned (selfRepo is an "owner/repo" slug). Matching is
// case-insensitive to mirror GitHub's handling of owner/repo names.
func isSelfReference(pkgName, selfRepo string) bool {
	if selfRepo == "" {
		return false
	}
	owner, repo := forge.SplitOwnerRepo(pkgName)
	if owner == "" || repo == "" {
		return false
	}
	return strings.EqualFold(owner+"/"+repo, selfRepo)
}

// isExpressionImageRef reports whether a container image package's reference is
// driven by a build-arg expression (e.g., FROM alpine:${ALPINE_TAG}). Such refs
// can't be statically pinned to a digest, so they are not actionable supply-chain
// findings. The dockerfilex extractor records this on the package metadata; we
// fall back to sniffing the raw reference for robustness.
func isExpressionImageRef(pkg *extractor.Package) bool {
	if meta, ok := pkg.Metadata.(*dockerfilex.BaseImageMetadata); ok {
		if meta.IsExpression {
			return true
		}
		if strings.Contains(meta.Raw, "${") {
			return true
		}
	}
	return strings.Contains(pkg.Version, "${")
}

// isContainerImageType reports whether the PURL type represents a container image.
func isContainerImageType(purlType string) bool {
	switch purlType {
	case purl.TypeDocker, purl.TypeOCI:
		return true
	}
	return false
}
