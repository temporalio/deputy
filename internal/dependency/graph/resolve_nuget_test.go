package graph

import (
	"testing"
)

func TestNuGetResolver_Ecosystem(t *testing.T) {
	r := NewNuGetResolver()
	if got := r.Ecosystem(); got != "NuGet" {
		t.Errorf("Ecosystem() = %q, want %q", got, "NuGet")
	}
}

func TestNuGetResolver_ResolveEdges_PackagesLockJSON(t *testing.T) {
	packagesLock := `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="
      },
      "Microsoft.Extensions.Logging": {
        "type": "Direct",
        "requested": "[7.0.0, )",
        "resolved": "7.0.0",
        "contentHash": "Nw2muoNrOG5U5qa1ZbXKXkhoQBN9E/d3bWDwMYX8+gNW7LY9k49vRJQREMCnm+Z8L8laNxL2a+nwGMhmJ9GTBQ==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "7.0.0",
          "Microsoft.Extensions.Logging.Abstractions": "7.0.0",
          "Microsoft.Extensions.Options": "7.0.0"
        }
      },
      "Microsoft.Extensions.DependencyInjection.Abstractions": {
        "type": "Transitive",
        "resolved": "7.0.0",
        "contentHash": "h3j/QfmFN4S0w4C2A6X7arXij/M/OVw3uQHSOFxnND4DyAzO1F9eMX7Eti7lU/OkSthEE0WzRsfT/Dmx86jzCw=="
      },
      "Microsoft.Extensions.Logging.Abstractions": {
        "type": "Transitive",
        "resolved": "7.0.0",
        "contentHash": "kmn78+LPVMOWeITUjIlfxUPDsI0R6G0RkeAMBmQxAJ7vBJn4q2dTva7pWi65ceN5vPGjJ9q/Uae2WKgvfktJAw=="
      },
      "Microsoft.Extensions.Options": {
        "type": "Transitive",
        "resolved": "7.0.0",
        "contentHash": "lP1yBnTTU42cKpMozuafbvNtQ7QcBjr/CcK3bYOGEMH55Fjt+iecXjT6chR7vbgCMqy3PG3aNQSZgo/EuY/9qQ==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "7.0.0",
          "Microsoft.Extensions.Primitives": "7.0.0"
        }
      },
      "Microsoft.Extensions.Primitives": {
        "type": "Transitive",
        "resolved": "7.0.0",
        "contentHash": "um1KU5kxcRp3CNuI8O/GmZtpRLNZdYdw9xy8LMz5X9Yw2Hns/+dnzVkNv/Tl5v0OB7BHuonPo9hZPUU9nM1o8w=="
      }
    }
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"packages.lock.json": []byte(packagesLock),
		},
	}

	g := New()
	r := NewNuGetResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have 6 packages
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 6 {
		t.Errorf("Expected 6 nodes, got %d", nodeCount)
	}

	// Check direct dependencies
	newtonsoftPURL := "pkg:nuget/Newtonsoft.Json@13.0.3"
	if node := g.Node(newtonsoftPURL); node == nil {
		t.Errorf("Expected node %s to exist", newtonsoftPURL)
	} else if !node.Direct {
		t.Errorf("Expected %s to be marked as direct", newtonsoftPURL)
	}

	loggingPURL := "pkg:nuget/Microsoft.Extensions.Logging@7.0.0"
	if node := g.Node(loggingPURL); node == nil {
		t.Errorf("Expected node %s to exist", loggingPURL)
	} else if !node.Direct {
		t.Errorf("Expected %s to be marked as direct", loggingPURL)
	}

	// Check transitive dependencies
	diPURL := "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@7.0.0"
	if node := g.Node(diPURL); node == nil {
		t.Errorf("Expected node %s to exist", diPURL)
	} else if node.Direct {
		t.Errorf("Expected %s to be marked as transitive", diPURL)
	}

	// Check edges exist
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount < 5 {
		t.Errorf("Expected at least 5 edges, got %d", edgeCount)
	}
}

func TestNuGetResolver_ResolveEdges_PackagesConfig(t *testing.T) {
	packagesConfig := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="log4net" version="2.0.15" targetFramework="net48" />
  <package id="NUnit" version="3.13.3" targetFramework="net48" />
</packages>`

	files := &mockFileReader{
		files: map[string][]byte{
			"packages.config": []byte(packagesConfig),
		},
	}

	g := New()
	r := NewNuGetResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have 3 packages
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 3 {
		t.Errorf("Expected 3 nodes, got %d", nodeCount)
	}

	// Check Newtonsoft.Json
	newtonsoftPURL := "pkg:nuget/Newtonsoft.Json@13.0.3"
	if node := g.Node(newtonsoftPURL); node == nil {
		t.Errorf("Expected node %s to exist", newtonsoftPURL)
	}

	// Check log4net
	log4netPURL := "pkg:nuget/log4net@2.0.15"
	if node := g.Node(log4netPURL); node == nil {
		t.Errorf("Expected node %s to exist", log4netPURL)
	}

	// Check NUnit
	nunitPURL := "pkg:nuget/NUnit@3.13.3"
	if node := g.Node(nunitPURL); node == nil {
		t.Errorf("Expected node %s to exist", nunitPURL)
	}

	// All should be marked as direct
	for node := range g.Nodes() {
		if !node.Direct {
			t.Errorf("Expected %s to be marked as direct in packages.config", node.Purl)
		}
	}
}

func TestNuGetResolver_ResolveEdges_NoFiles(t *testing.T) {
	files := &mockFileReader{
		files: map[string][]byte{},
	}

	g := New()
	r := NewNuGetResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have no nodes
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 0 {
		t.Errorf("Expected 0 nodes, got %d", nodeCount)
	}
}

func TestNuGetPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Newtonsoft.Json",
			version: "13.0.3",
			want:    "pkg:nuget/Newtonsoft.Json@13.0.3",
		},
		{
			name:    "Microsoft.Extensions.Logging",
			version: "7.0.0",
			want:    "pkg:nuget/Microsoft.Extensions.Logging@7.0.0",
		},
		{
			name:    "SomePackage",
			version: "",
			want:    "pkg:nuget/SomePackage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nugetPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("nugetPkgToPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
