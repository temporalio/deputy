package advisorysource

import (
	"context"
	"slices"
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/ecosystem"
)

// SourceNameOSV is the provenance name recorded for OSV-derived findings.
const SourceNameOSV = "osv"

// osvSource is the built-in advisory source backed by the OSV database. It
// implements [Source] so it is interchangeable with future plugin sources.
type osvSource struct {
	client osv.Client
}

// NewOSVSource returns the built-in OSV advisory source. A nil client uses a
// default OSV client.
func NewOSVSource(client osv.Client) Source {
	if client == nil {
		client = osv.NewClient()
	}
	return &osvSource{client: client}
}

// osvArtifactKinds are the artifact kinds OSV can answer for. It does not cover
// container base-image references (those are inventory-only).
var osvArtifactKinds = []vulnerabilityv1.ArtifactKind{
	vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE,
	vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_OS_PACKAGE,
	vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION,
}

// Info reports OSV coverage, derived from the ecosystem registry so it can never
// drift from what the OSV query path actually supports.
func (s *osvSource) Info() *pluginv1.AdvisorySourceInfo {
	ecos := make([]string, 0)
	for _, e := range ecosystem.All() {
		if e.OSVQueryable() {
			ecos = append(ecos, e.String())
		}
	}
	// GitHub Actions is served from OSV's advisory bucket rather than the
	// package registry, so it is not an OSVQueryable ecosystem; declare it
	// explicitly so routing covers action refs.
	ecos = append(ecos, EcosystemGitHubActions)
	// OS-package families (Alpine, Debian, ...) also live outside the
	// package-manager registry; declare them lowercased to match how classify
	// canonicalizes OS packages, so container-image OS packages route here.
	for _, fam := range osv.OSFamilies() {
		ecos = append(ecos, strings.ToLower(fam))
	}
	slices.Sort(ecos)
	return &pluginv1.AdvisorySourceInfo{
		Name:        SourceNameOSV,
		DisplayName: "OSV",
		Description: "Open Source Vulnerabilities database (CVE/GHSA/Go vuln DB and malicious-package advisories).",
		Version:     1,
		Capabilities: &pluginv1.SourceCapabilities{
			Ecosystems:   ecos,
			Artifacts:    slices.Clone(osvArtifactKinds),
			FindingKinds: []vulnerabilityv1.FindingKind{vulnerabilityv1.FindingKind_FINDING_KIND_VULNERABILITY, vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE},
		},
	}
}

// Query runs the OSV lookup and tags each result with OSV provenance and the
// advisory's finding kind (malware vs vulnerability). It consumes and returns
// proto types directly (osv.QueryProto), so there is no conversion at this seam.
//
// Advisories OSV reported but would not serve records for are reported as
// warnings rather than errors, so one withdrawn record cannot cost the caller
// every other package's findings.
func (s *osvSource) Query(ctx context.Context, pkgs []*dependencyv1.Package) (*Result, error) {
	findings, advisories, unresolved, err := osv.QueryProto(ctx, s.client, pkgs)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		if f != nil {
			f.Sources = []string{SourceNameOSV}
		}
	}
	for _, adv := range advisories {
		if adv == nil {
			continue
		}
		adv.Kind = AdvisoryKind(adv)
	}
	return &Result{Findings: findings, Advisories: advisories, Warnings: osv.AdvisoryWarnings(unresolved)}, nil
}

// AdvisoryKind classifies an advisory as malware or vulnerability. OSV publishes
// malicious-package records under the "MAL-" identifier prefix, on either the
// record itself or one of its aliases. It is exported so every surface that
// serves OSV advisories (scan findings, advisory lookups) classifies them
// identically.
func AdvisoryKind(adv *vulnerabilityv1.Advisory) vulnerabilityv1.FindingKind {
	if isMalwareID(adv.GetId()) || slices.ContainsFunc(adv.GetAliases(), isMalwareID) {
		return vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE
	}
	return vulnerabilityv1.FindingKind_FINDING_KIND_VULNERABILITY
}

func isMalwareID(id string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "MAL-")
}
