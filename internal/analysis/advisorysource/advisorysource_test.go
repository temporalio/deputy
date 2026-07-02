package advisorysource

import (
	"context"
	"slices"
	"testing"

	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// fakeSource is a configurable Source for exercising registry behavior without
// hitting a real advisory database.
type fakeSource struct {
	name       string
	ecosystems []string
	artifacts  []vulnerabilityv1.ArtifactKind
	findings   []vulnerability.Finding
	advisories map[string]*vulnerabilityv1.Advisory
}

func (f *fakeSource) Info() *pluginv1.AdvisorySourceInfo {
	return &pluginv1.AdvisorySourceInfo{
		Name: f.name,
		Capabilities: &pluginv1.SourceCapabilities{
			Ecosystems: f.ecosystems,
			Artifacts:  f.artifacts,
		},
	}
}

func (f *fakeSource) Query(_ context.Context, _ []osv.PkgInput) (*Result, error) {
	return &Result{Findings: f.findings, Advisories: f.advisories}, nil
}

func goInput(name, version string) osv.PkgInput {
	return osv.PkgInput{QueryKey: osv.QueryKey{Name: name, Version: version, Ecosystem: "go", PURL: "pkg:golang/" + name + "@" + version}}
}

func goFinding(advID, source, name, version string) vulnerability.Finding {
	return vulnerability.Finding{
		AdvisoryID: advID,
		Dependency: dependency.ID{Name: name, Ecosystem: "go", PURL: "pkg:golang/" + name + "@" + version},
		Version:    version,
		Sources:    []string{source},
		Affected:   true,
	}
}

func onlyPackage(art vulnerabilityv1.ArtifactKind) []vulnerabilityv1.ArtifactKind {
	return []vulnerabilityv1.ArtifactKind{art}
}

func TestRegistryRoutesAndReportsCoverage(t *testing.T) {
	src := &fakeSource{
		name:       "osv",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE),
		findings:   []vulnerability.Finding{goFinding("CVE-1", "osv", "github.com/foo/bar", "1.0.0")},
		advisories: map[string]*vulnerabilityv1.Advisory{"CVE-1": {Id: "CVE-1"}},
	}
	reg := NewRegistry(src)

	dockerPkg := osv.PkgInput{QueryKey: osv.QueryKey{Name: "alpine", Version: "3.19", Ecosystem: "docker", PURL: "pkg:docker/library/alpine@3.19"}}
	got, err := reg.Query(context.Background(), []osv.PkgInput{goInput("github.com/foo/bar", "1.0.0"), dockerPkg})
	if err != nil {
		t.Fatalf("Query error = %v, want nil (uncovered package must not fail the scan)", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].AdvisoryID != "CVE-1" {
		t.Fatalf("findings = %+v, want the single go finding", got.Findings)
	}
	if !hasCoverage(got.Coverage.GetCovered(), "go", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE, "osv") {
		t.Errorf("covered missing go/PACKAGE by osv: %+v", got.Coverage.GetCovered())
	}
	if !hasCoverage(got.Coverage.GetUncovered(), "docker", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF) {
		t.Errorf("uncovered missing docker/CONTAINER_IMAGE_REF: %+v", got.Coverage.GetUncovered())
	}
}

func TestRegistryUnionWithProvenance(t *testing.T) {
	shared := "CVE-SHARED"
	a := &fakeSource{
		name: "a", ecosystems: []string{"go"}, artifacts: onlyPackage(vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE),
		findings: []vulnerability.Finding{goFinding(shared, "a", "github.com/foo/bar", "1.0.0")},
	}
	b := &fakeSource{
		name: "b", ecosystems: []string{"go"}, artifacts: onlyPackage(vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE),
		findings: []vulnerability.Finding{
			goFinding(shared, "b", "github.com/foo/bar", "1.0.0"),
			goFinding("CVE-ONLY-B", "b", "github.com/foo/bar", "1.0.0"),
		},
	}
	reg := NewRegistry(a, b)

	got, err := reg.Query(context.Background(), []osv.PkgInput{goInput("github.com/foo/bar", "1.0.0")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (shared merged + b-only)", len(got.Findings))
	}
	var merged *vulnerability.Finding
	for i := range got.Findings {
		if got.Findings[i].AdvisoryID == shared {
			merged = &got.Findings[i]
		}
	}
	if merged == nil {
		t.Fatalf("shared finding missing")
	}
	if !slices.Equal(merged.Sources, []string{"a", "b"}) {
		t.Fatalf("shared finding sources = %v, want [a b] (union-with-provenance)", merged.Sources)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		in      osv.PkgInput
		wantEco string
		wantArt vulnerabilityv1.ArtifactKind
	}{
		{"go", goInput("x", "1"), "go", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE},
		{"docker eco", osv.PkgInput{QueryKey: osv.QueryKey{Ecosystem: "docker"}}, "docker", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF},
		{"docker purl", osv.PkgInput{QueryKey: osv.QueryKey{PURL: "pkg:docker/library/alpine@3.19"}}, "docker", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF},
		{"deb os pkg", osv.PkgInput{QueryKey: osv.QueryKey{Ecosystem: "deb"}}, "deb", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_OS_PACKAGE},
		{"github actions eco", osv.PkgInput{QueryKey: osv.QueryKey{Ecosystem: "github-actions"}}, EcosystemGitHubActions, vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION},
		{"gha alias", osv.PkgInput{QueryKey: osv.QueryKey{Ecosystem: "gha"}}, EcosystemGitHubActions, vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, art := classify(tt.in)
			if eco != tt.wantEco || art != tt.wantArt {
				t.Fatalf("classify = (%q, %v), want (%q, %v)", eco, art, tt.wantEco, tt.wantArt)
			}
		})
	}
}

func TestAdvisoryKind(t *testing.T) {
	tests := []struct {
		name string
		adv  *vulnerabilityv1.Advisory
		want vulnerabilityv1.FindingKind
	}{
		{"malware id", &vulnerabilityv1.Advisory{Id: "MAL-2024-1"}, vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE},
		{"malware alias", &vulnerabilityv1.Advisory{Id: "GHSA-x", Aliases: []string{"MAL-2024-2"}}, vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE},
		{"cve", &vulnerabilityv1.Advisory{Id: "CVE-2024-1"}, vulnerabilityv1.FindingKind_FINDING_KIND_VULNERABILITY},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := advisoryKind(tt.adv); got != tt.want {
				t.Fatalf("advisoryKind = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOSVSourceInfo(t *testing.T) {
	info := NewOSVSource(nil).Info()
	if info.GetName() != SourceNameOSV {
		t.Fatalf("name = %q, want %q", info.GetName(), SourceNameOSV)
	}
	caps := info.GetCapabilities()
	if !slices.Contains(caps.GetEcosystems(), "go") {
		t.Errorf("ecosystems missing go: %v", caps.GetEcosystems())
	}
	if !slices.Contains(caps.GetEcosystems(), EcosystemGitHubActions) {
		t.Errorf("ecosystems missing github-actions: %v", caps.GetEcosystems())
	}
	if !slices.Contains(caps.GetArtifacts(), vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION) {
		t.Errorf("artifacts missing GITHUB_ACTION: %v", caps.GetArtifacts())
	}
	if slices.Contains(caps.GetArtifacts(), vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF) {
		t.Errorf("OSV should not claim CONTAINER_IMAGE_REF coverage")
	}
	if !slices.Contains(caps.GetFindingKinds(), vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE) {
		t.Errorf("finding kinds missing MALWARE: %v", caps.GetFindingKinds())
	}
}

func hasCoverage(entries []*vulnerabilityv1.CoverageEntry, eco string, art vulnerabilityv1.ArtifactKind, sources ...string) bool {
	for _, e := range entries {
		if e.GetEcosystem() != eco || e.GetArtifact() != art {
			continue
		}
		for _, s := range sources {
			if !slices.Contains(e.GetSources(), s) {
				return false
			}
		}
		return true
	}
	return false
}
