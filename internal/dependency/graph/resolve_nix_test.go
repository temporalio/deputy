package graph_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/deputy/internal/dependency/graph"
)

func TestNixFlakeResolver_Ecosystem(t *testing.T) {
	r := graph.NewNixFlakeResolver()
	if r.Ecosystem() != "Nix" {
		t.Errorf("Ecosystem() = %q, want %q", r.Ecosystem(), "Nix")
	}
}

func TestNixFlakeResolver_ResolveEdges(t *testing.T) {
	// Create a temporary directory with a flake.lock
	tmpDir := t.TempDir()
	lockContent := `{
  "nodes": {
    "nixpkgs": {
      "locked": {
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "a3a3dda3bacf61e8a39258a0ed9c924eeca8e293",
        "type": "github"
      },
      "original": {
        "owner": "NixOS",
        "ref": "nixos-unstable",
        "repo": "nixpkgs",
        "type": "github"
      }
    },
    "flake-utils": {
      "inputs": {
        "systems": "systems"
      },
      "locked": {
        "owner": "numtide",
        "repo": "flake-utils",
        "rev": "b1d9ab70662946ef0850d488da1c9019f3a9752a",
        "type": "github"
      },
      "original": {
        "owner": "numtide",
        "repo": "flake-utils",
        "type": "github"
      }
    },
    "systems": {
      "locked": {
        "owner": "nix-systems",
        "repo": "default",
        "rev": "da67096a3b9bf56a91d16901293e51ba5b49a27e",
        "type": "github"
      },
      "original": {
        "owner": "nix-systems",
        "repo": "default",
        "type": "github"
      }
    },
    "root": {
      "inputs": {
        "nixpkgs": "nixpkgs",
        "flake-utils": "flake-utils"
      }
    }
  },
  "root": "root",
  "version": 7
}`

	err := os.WriteFile(filepath.Join(tmpDir, "flake.lock"), []byte(lockContent), 0644)
	if err != nil {
		t.Fatalf("failed to write flake.lock: %v", err)
	}

	// Create an empty graph
	g := graph.New()

	// Create file reader
	reader := &testFileReader{root: tmpDir}

	// Resolve edges - this should not error even with no matching nodes
	r := graph.NewNixFlakeResolver()
	err = r.ResolveEdges(context.Background(), g, reader)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}
}

// testFileReader implements graph.FileReader for testing
type testFileReader struct {
	root string
}

func (r *testFileReader) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(r.root, path))
}
