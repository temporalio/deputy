package graph

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/picatz/deputy/internal/inventory/plugins/terraform"
)

type mapFileReader struct {
	fstest.MapFS
}

func (m mapFileReader) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(m.MapFS, name)
}

func TestTerraformResolverEdges(t *testing.T) {
	fsys := mapFileReader{MapFS: fstest.MapFS{
		"main.tf": {
			Data: []byte(`terraform {
  required_version = ">= 1.5.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = "~> 3.1"
  }
}`),
		},
		"modules/app/main.tf": {
			Data: []byte(`terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.42.0"
    }
  }
}`),
		},
	}}

	g := New()
	coreReq := terraform.Requirement{Kind: terraform.RequirementTerraformCore, Name: "terraform", Version: ">= 1.5.7"}
	awsReq := terraform.Requirement{Kind: terraform.RequirementTerraformProvider, Name: "hashicorp/aws", Version: "~> 5.0"}

	g.AddNode(&Node{Purl: terraformRequirementPURL(coreReq), Name: coreReq.Name, Version: coreReq.Version})
	g.AddNode(&Node{Purl: terraformRequirementPURL(awsReq), Name: awsReq.Name, Version: awsReq.Version})

	resolver := NewTerraformResolver()
	if err := resolver.ResolveEdges(context.Background(), g, fsys); err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	rootModulePURL := terraformModulePURL(".")
	module := g.Node(rootModulePURL)
	if module == nil {
		t.Fatalf("expected module node %q", rootModulePURL)
	}
	if !module.Direct {
		t.Errorf("expected module node to be direct")
	}
	if module.Depth != 0 {
		t.Errorf("expected module node depth 0, got %d", module.Depth)
	}

	if !hasEdge(g, rootModulePURL, terraformRequirementPURL(coreReq)) {
		t.Errorf("expected edge from module to terraform core")
	}
	if !hasEdge(g, rootModulePURL, terraformRequirementPURL(awsReq)) {
		t.Errorf("expected edge from module to aws provider")
	}

	randomReq := terraform.Requirement{Kind: terraform.RequirementTerraformProvider, Name: "hashicorp/random", Version: "~> 3.1"}
	if g.Node(terraformRequirementPURL(randomReq)) == nil {
		t.Errorf("expected random provider node to be created")
	}

	paths := g.PathsTo(terraformRequirementPURL(awsReq))
	if !pathsContainRoot(paths, rootModulePURL) {
		t.Errorf("expected module path to aws in PathsTo")
	}

	modulePURL := terraformModulePURL("modules/app")
	if g.Node(modulePURL) == nil {
		t.Errorf("expected module node for nested module")
	}
}

func hasEdge(g *Graph, from, to string) bool {
	for edge := range g.Edges() {
		if edge.From == from && edge.To == to {
			return true
		}
	}
	return false
}

func pathsContainRoot(paths []Path, rootPURL string) bool {
	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		if p[0].Purl == rootPURL {
			return true
		}
	}
	return false
}
