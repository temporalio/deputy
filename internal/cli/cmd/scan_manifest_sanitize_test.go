package cmd

import (
	"slices"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
)

// TestWithoutInternalManifestMetadata verifies that user-facing JSON output is
// stripped of Deputy's internal component-key routing group, while the original
// response (used for in-process remediation) keeps it.
func TestWithoutInternalManifestMetadata(t *testing.T) {
	ref := &dependencyv1.ManifestRef{Path: "mise.toml", Manager: "mise", Groups: []string{"prod"}}
	dependency.SetManifestRefComponentKey(ref, "go")

	resp := &scanv1.ScanResponse{
		Findings: []*vulnerabilityv1.Finding{
			{Package: &dependencyv1.Package{ManifestRefs: []*dependencyv1.ManifestRef{ref}}},
		},
		Packages: []*dependencyv1.Package{
			{ManifestRefs: []*dependencyv1.ManifestRef{ref}},
		},
	}

	clone := withoutInternalManifestMetadata(resp)

	// The original must keep the internal key so remediation stays source-aware.
	if got := dependency.ManifestRefComponentKey(resp.Findings[0].Package.ManifestRefs[0]); got != "go" {
		t.Errorf("original lost component key: %q", got)
	}

	cloneRef := clone.Findings[0].Package.ManifestRefs[0]
	if got := dependency.ManifestRefComponentKey(cloneRef); got != "" {
		t.Errorf("clone still leaks internal component-key group: groups=%v", cloneRef.Groups)
	}
	if !slices.Contains(cloneRef.Groups, "prod") {
		t.Errorf("clone dropped the public group: %v", cloneRef.Groups)
	}
	if slices.ContainsFunc(clone.Packages[0].ManifestRefs[0].Groups, func(g string) bool {
		return g == "deputy:component-key=go"
	}) {
		t.Errorf("clone Packages still leak internal group: %v", clone.Packages[0].ManifestRefs[0].Groups)
	}
}

// TestWithoutInternalManifestMetadataNil ensures a nil response is handled.
func TestWithoutInternalManifestMetadataNil(t *testing.T) {
	if got := withoutInternalManifestMetadata(nil); got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}
}
