package inventory

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

func TestSBOMDocToPackagesPreservesMiseLockedVersion(t *testing.T) {
	doc := sbom.NewDocument()
	node := sbom.NewNode()
	node.Name = "go"
	node.Version = "1.20.1"
	node.Identifiers = map[int32]string{
		int32(sbom.SoftwareIdentifierType_PURL): purlx.MisePURL("go", "1.20.1"),
	}
	node.Properties = append(node.Properties,
		&sbom.Property{Name: "deputy:requestedVersion", Data: "1.20"},
		&sbom.Property{Name: "deputy:lockedVersion", Data: "1.20.1"},
		&sbom.Property{Name: "deputy:location", Data: "mise.toml"},
	)
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)

	pkgs := sbomDocToPackages(doc)
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	md, ok := pkgs[0].Metadata.(*mise.Metadata)
	if !ok {
		t.Fatalf("metadata type = %T, want *mise.Metadata", pkgs[0].Metadata)
	}
	if pkgs[0].Version != "1.20.1" {
		t.Errorf("Version = %q, want 1.20.1", pkgs[0].Version)
	}
	if md.Version != "1.20" {
		t.Errorf("metadata Version = %q, want 1.20", md.Version)
	}
	if md.LockedVersion != "1.20.1" {
		t.Errorf("LockedVersion = %q, want 1.20.1", md.LockedVersion)
	}
	if len(dependency.PackagePaths(pkgs[0])) != 1 || dependency.PackagePaths(pkgs[0])[0] != "mise.toml" {
		t.Errorf("Locations = %v, want [mise.toml]", dependency.PackagePaths(pkgs[0]))
	}
}
