package fixresolve

import (
	"context"
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// fakeResolver answers existence from a fixed map keyed by "module@version",
// falling back to deflt for anything unspecified.
type fakeResolver struct {
	exists map[string]Existence
	deflt  Existence
}

func (f fakeResolver) ModuleVersionExists(_ context.Context, module, version string) Existence {
	if e, ok := f.exists[module+"@"+version]; ok {
		return e
	}
	return f.deflt
}

func pf(module string, versions ...string) *vulnerabilityv1.PackageFix {
	return &vulnerabilityv1.PackageFix{Module: module, Ecosystem: "Go", FixedVersions: versions}
}

func TestResolve_DockerMigration(t *testing.T) {
	c := vulnerability.Consolidated{
		Package:       "github.com/docker/docker",
		Version:       "v28.5.2+incompatible",
		Ecosystem:     "Go",
		FixedVersions: []string{"29.3.1"},
		PackageFixes: []*vulnerabilityv1.PackageFix{
			pf("github.com/docker/docker", "29.3.1"),
			pf("github.com/moby/moby/v2", "2.0.0-beta.8", "2.0.0-beta.14"),
		},
	}
	r := fakeResolver{
		exists: map[string]Existence{
			"github.com/moby/moby/v2@2.0.0-beta.8": ExistsYes,
		},
		deflt: ExistsNo, // docker/docker@29.3.1 absent
	}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusMigration {
		t.Fatalf("expected migration verdict, got %+v", v)
	}
	if v.TargetModule != "github.com/moby/moby/v2" {
		t.Errorf("target module = %q, want github.com/moby/moby/v2", v.TargetModule)
	}
	if v.Version != "2.0.0-beta.8" {
		t.Errorf("version = %q, want 2.0.0-beta.8 (lowest fix)", v.Version)
	}
	if v.Claimed != "29.3.1" {
		t.Errorf("claimed = %q, want 29.3.1", v.Claimed)
	}
}

func TestResolve_MigrationWhenNoInPlaceClaim(t *testing.T) {
	// Mirrors CVE-2026-41567: docker/docker is last_affected (no fix event), the
	// fix lives only on moby/moby/v2.
	c := vulnerability.Consolidated{
		Package:   "github.com/docker/docker",
		Version:   "v28.5.2+incompatible",
		Ecosystem: "Go",
		PackageFixes: []*vulnerabilityv1.PackageFix{
			pf("github.com/moby/moby/v2", "2.0.0-beta.14"),
		},
	}
	r := fakeResolver{exists: map[string]Existence{"github.com/moby/moby/v2@2.0.0-beta.14": ExistsYes}, deflt: ExistsNo}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusMigration {
		t.Fatalf("expected migration verdict, got %+v", v)
	}
	if v.TargetModule != "github.com/moby/moby/v2" || v.Version != "2.0.0-beta.14" {
		t.Errorf("got target %q version %q", v.TargetModule, v.Version)
	}
}

func TestResolve_MechanicalMajorBump(t *testing.T) {
	// No curated table entry: relies solely on the foo -> foo/vN rule.
	c := vulnerability.Consolidated{
		Package:       "github.com/example/widget",
		Version:       "v1.4.0",
		Ecosystem:     "Go",
		FixedVersions: []string{"2.0.0"},
		PackageFixes: []*vulnerabilityv1.PackageFix{
			pf("github.com/example/widget", "2.0.0"),
			pf("github.com/example/widget/v2", "2.0.1"),
		},
	}
	r := fakeResolver{exists: map[string]Existence{"github.com/example/widget/v2@2.0.1": ExistsYes}, deflt: ExistsNo}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusMigration {
		t.Fatalf("expected migration verdict, got %+v", v)
	}
	if v.TargetModule != "github.com/example/widget/v2" || v.Version != "2.0.1" {
		t.Errorf("got target %q version %q", v.TargetModule, v.Version)
	}
}

func TestResolve_InPlaceVerified(t *testing.T) {
	c := vulnerability.Consolidated{
		Package:       "golang.org/x/net",
		Version:       "v0.47.0",
		Ecosystem:     "Go",
		FixedVersions: []string{"0.55.0"},
	}
	r := fakeResolver{exists: map[string]Existence{"golang.org/x/net@0.55.0": ExistsYes}}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusInPlace {
		t.Fatalf("expected in-place verdict, got %+v", v)
	}
	if v.Version != "0.55.0" || !v.HasActionableUpgrade() {
		t.Errorf("expected actionable upgrade 0.55.0, got %+v", v)
	}
}

func TestResolve_UnverifiedWhenProxyUnknown(t *testing.T) {
	c := vulnerability.Consolidated{
		Package:       "golang.org/x/net",
		Version:       "v0.47.0",
		Ecosystem:     "Go",
		FixedVersions: []string{"0.55.0"},
	}
	r := fakeResolver{deflt: ExistsUnknown}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusUnverified {
		t.Fatalf("expected unverified verdict, got %+v", v)
	}
	if v.Version != "0.55.0" {
		t.Errorf("expected claimed version preserved, got %q", v.Version)
	}
}

func TestResolve_UnavailableWhenAbsentAndNoMigration(t *testing.T) {
	c := vulnerability.Consolidated{
		Package:       "github.com/lonely/pkg",
		Version:       "v1.0.0",
		Ecosystem:     "Go",
		FixedVersions: []string{"1.2.3"},
	}
	r := fakeResolver{deflt: ExistsNo}

	v := Resolve(t.Context(), c, r, Options{Verify: true})
	if v == nil || v.Status != vulnerability.FixStatusUnavailable {
		t.Fatalf("expected unavailable verdict, got %+v", v)
	}
	if v.Claimed != "1.2.3" {
		t.Errorf("expected claimed 1.2.3 retained, got %q", v.Claimed)
	}
}

func TestResolve_SkippedForNonGoAndDisabled(t *testing.T) {
	c := vulnerability.Consolidated{Package: "left-pad", Version: "1.0.0", Ecosystem: "npm", FixedVersions: []string{"1.0.1"}}
	r := fakeResolver{deflt: ExistsYes}

	if v := Resolve(t.Context(), c, r, Options{Verify: true}); v != nil {
		t.Errorf("expected nil for non-Go ecosystem, got %+v", v)
	}
	goC := vulnerability.Consolidated{Package: "golang.org/x/net", Version: "v0.47.0", Ecosystem: "Go", FixedVersions: []string{"0.55.0"}}
	if v := Resolve(t.Context(), goC, r, Options{Verify: false}); v != nil {
		t.Errorf("expected nil when verification disabled, got %+v", v)
	}
}

func TestGoVersionForms(t *testing.T) {
	tests := []struct {
		module  string
		version string
		want    []string
	}{
		{"github.com/docker/docker", "29.3.1", []string{"v29.3.1", "v29.3.1+incompatible"}},
		{"github.com/moby/moby/v2", "2.0.0-beta.8", []string{"v2.0.0-beta.8"}},
		{"golang.org/x/net", "0.55.0", []string{"v0.55.0"}},
		{"github.com/foo/bar", "v1.2.3", []string{"v1.2.3"}},
	}
	for _, tc := range tests {
		got := goVersionForms(tc.module, tc.version)
		if len(got) != len(tc.want) {
			t.Errorf("goVersionForms(%q,%q) = %v, want %v", tc.module, tc.version, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("goVersionForms(%q,%q) = %v, want %v", tc.module, tc.version, got, tc.want)
				break
			}
		}
	}
}

func TestIsSuccessorPath(t *testing.T) {
	tests := []struct {
		base, candidate string
		want            bool
	}{
		{"github.com/docker/docker", "github.com/moby/moby/v2", true}, // curated rename
		{"github.com/foo/bar", "github.com/foo/bar/v2", true},         // mechanical bump
		{"github.com/foo/bar/v2", "github.com/foo/bar/v3", true},
		{"github.com/foo/bar/v3", "github.com/foo/bar/v2", false}, // wrong direction
		{"github.com/foo/bar", "github.com/other/bar/v2", false},
		{"github.com/foo/bar", "github.com/foo/bar", false},
	}
	for _, tc := range tests {
		if got := isSuccessorPath(tc.base, tc.candidate); got != tc.want {
			t.Errorf("isSuccessorPath(%q,%q) = %v, want %v", tc.base, tc.candidate, got, tc.want)
		}
	}
}
