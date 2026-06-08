package scanning

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

func TestPackagesToInputsUsesMiseLockedVersion(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "go",
		Version:   "1.20",
		PURLType:  purlx.TypeMise,
		Locations: []string{"mise.toml"},
		Metadata:  &mise.Metadata{LockedVersion: "1.20.1"},
	}

	inputs := packagesToInputs([]*extractor.Package{pkg}, nil)
	if len(inputs) != 2 {
		t.Fatalf("got %d inputs, want stdlib and toolchain", len(inputs))
	}
	for _, in := range inputs {
		if in.Version != "1.20.1" {
			t.Errorf("%s version = %q, want 1.20.1", in.Name, in.Version)
		}
		if !in.IsDirect {
			t.Errorf("%s should be direct", in.Name)
		}
		if len(in.ManifestRefs) != 1 || dependency.ManifestRefComponentKey(&in.ManifestRefs[0]) != "go" {
			t.Errorf("%s manifest refs = %+v, want component key go", in.Name, in.ManifestRefs)
		}
	}
}
