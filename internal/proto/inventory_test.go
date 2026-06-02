package proto

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	"github.com/temporalio/deputy/internal/purlx"
)

func TestBuildInventoryStats_CustomToolchainsAreDirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "node", Version: "20.11.0", PURLType: purlx.TypeMise},
		{Name: "golang", Version: "1.26.2", PURLType: purlx.TypeAsdf},
	}

	stats := buildInventoryStats(pkgs, nil)

	if stats.DirectPackages != 2 {
		t.Errorf("DirectPackages = %d, want 2", stats.DirectPackages)
	}
	if stats.TransitivePackages != 0 {
		t.Errorf("TransitivePackages = %d, want 0", stats.TransitivePackages)
	}
	if stats.ByEcosystem["mise"] != 1 {
		t.Errorf("mise count = %d, want 1", stats.ByEcosystem["mise"])
	}
	if stats.ByEcosystem["asdf"] != 1 {
		t.Errorf("asdf count = %d, want 1", stats.ByEcosystem["asdf"])
	}
}
