package scanning

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

func TestPackagesToProtoUsesMiseLockedVersion(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "go",
		Version:   "1.20",
		PURLType:  purlx.TypeMise,
		Locations: []string{"mise.toml"},
		Metadata:  &mise.Metadata{LockedVersion: "1.20.1"},
	}

	inputs := packagesToProto([]*extractor.Package{pkg}, nil)
	if len(inputs) != 2 {
		t.Fatalf("got %d inputs, want stdlib and toolchain", len(inputs))
	}
	for _, in := range inputs {
		if in.GetVersion() != "1.20.1" {
			t.Errorf("%s version = %q, want 1.20.1", in.GetName(), in.GetVersion())
		}
		if !in.GetDirect() {
			t.Errorf("%s should be direct", in.GetName())
		}
		if len(in.GetManifestRefs()) != 1 || dependency.ManifestRefComponentKey(in.GetManifestRefs()[0]) != "go" {
			t.Errorf("%s manifest refs = %+v, want component key go", in.GetName(), in.GetManifestRefs())
		}
	}
}
