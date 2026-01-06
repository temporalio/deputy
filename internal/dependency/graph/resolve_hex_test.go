package graph

import (
	"context"
	"testing"
)

func TestHexResolver_Ecosystem(t *testing.T) {
	r := NewHexResolver()
	if got := r.Ecosystem(); got != "Hex" {
		t.Errorf("Ecosystem() = %q, want %q", got, "Hex")
	}
}

func TestHexResolver_ResolveEdges_MixLock(t *testing.T) {
	mixLock := `%{
  "castore": {:hex, :castore, "1.0.5", "9ecdbb0aada6c38b62e0efe9e1e6e8b4c7a86b48", [:mix], [], "hexpm", "5a1f9a166b0a3f3ad5b3b8ab8c71b7f9e9d3e3c0"},
  "cowboy": {:hex, :cowboy, "2.10.0", "ff9b1db5fdfc92bac7f9f3c9b673f8e09e3ef6b3", [:make, :rebar3], [{:cowlib, "~> 2.12", [hex: :cowlib, repo: "hexpm", optional: false]}, {:ranch, "~> 1.8", [hex: :ranch, repo: "hexpm", optional: false]}], "hexpm", "3ffc7a7d1c3c5dffc0a1d1dd7a3ce35dba6d7a0a"},
  "cowlib": {:hex, :cowlib, "2.12.1", "a9fa6c32e8a8f25cec0d17aabf7d8e7a53b0f6e9", [:make, :rebar3], [], "hexpm", "1e7eb3e3a47e8f54e12e3c5b6e3c0c7f8a9d5a3b"},
  "jason": {:hex, :jason, "1.4.1", "c9e8e9a9a1e8b1e3d4c5f6a7b8c9d0e1f2a3b4c5", [:mix], [{:decimal, "~> 1.0 or ~> 2.0", [hex: :decimal, repo: "hexpm", optional: true]}], "hexpm", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"},
  "phoenix": {:hex, :phoenix, "1.7.10", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", [:mix], [{:castore, ">= 0.0.0", [hex: :castore, repo: "hexpm", optional: false]}, {:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: true]}, {:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}], "hexpm", "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"},
  "plug": {:hex, :plug, "1.15.2", "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", [:mix], [], "hexpm", "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"},
  "ranch": {:hex, :ranch, "1.8.0", "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", [:make, :rebar3], [], "hexpm", "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"},
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"mix.lock": []byte(mixLock),
		},
	}

	g := New()
	r := NewHexResolver()

	err := r.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have 7 packages
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 7 {
		t.Errorf("Expected 7 nodes, got %d", nodeCount)
	}

	// Check specific packages
	testCases := []struct {
		purl    string
		name    string
		version string
	}{
		{"pkg:hex/castore@1.0.5", "castore", "1.0.5"},
		{"pkg:hex/cowboy@2.10.0", "cowboy", "2.10.0"},
		{"pkg:hex/cowlib@2.12.1", "cowlib", "2.12.1"},
		{"pkg:hex/jason@1.4.1", "jason", "1.4.1"},
		{"pkg:hex/phoenix@1.7.10", "phoenix", "1.7.10"},
		{"pkg:hex/plug@1.15.2", "plug", "1.15.2"},
		{"pkg:hex/ranch@1.8.0", "ranch", "1.8.0"},
	}

	for _, tc := range testCases {
		node := g.Node(tc.purl)
		if node == nil {
			t.Errorf("Expected node %s to exist", tc.purl)
			continue
		}
		if node.Name != tc.name {
			t.Errorf("Expected node name %q, got %q", tc.name, node.Name)
		}
		if node.Version != tc.version {
			t.Errorf("Expected node version %q, got %q", tc.version, node.Version)
		}
		if node.Ecosystem != "Hex" {
			t.Errorf("Expected ecosystem Hex, got %q", node.Ecosystem)
		}
	}
}

func TestHexResolver_ResolveEdges_GitDependency(t *testing.T) {
	mixLock := `%{
  "mylib": {:git, "https://github.com/owner/mylib.git", "abc123def456", [branch: "main"]},
  "another": {:hex, :another, "0.1.0", "a1b2c3d4", [:mix], [], "hexpm", "e5f6a7b8"},
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"mix.lock": []byte(mixLock),
		},
	}

	g := New()
	r := NewHexResolver()

	err := r.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have 2 packages
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 2 {
		t.Errorf("Expected 2 nodes, got %d", nodeCount)
	}

	// Git dependency (no version)
	gitPURL := "pkg:hex/mylib"
	if node := g.Node(gitPURL); node == nil {
		t.Errorf("Expected git dependency node %s to exist", gitPURL)
	}

	// Hex dependency (with version)
	hexPURL := "pkg:hex/another@0.1.0"
	if node := g.Node(hexPURL); node == nil {
		t.Errorf("Expected hex dependency node %s to exist", hexPURL)
	}
}

func TestHexResolver_ResolveEdges_NoFiles(t *testing.T) {
	files := &mockFileReader{
		files: map[string][]byte{},
	}

	g := New()
	r := NewHexResolver()

	err := r.ResolveEdges(context.Background(), g, files)
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

func TestHexPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "phoenix",
			version: "1.7.10",
			want:    "pkg:hex/phoenix@1.7.10",
		},
		{
			name:    "castore",
			version: "1.0.5",
			want:    "pkg:hex/castore@1.0.5",
		},
		{
			name:    "mylib",
			version: "",
			want:    "pkg:hex/mylib",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("hexPkgToPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHexResolver_ParseMixLock(t *testing.T) {
	r := NewHexResolver()

	// Test complex mix.lock with various formats
	mixLock := []byte(`%{
  "bandit": {:hex, :bandit, "1.1.1", "a2c52fd6e97cd2fa9a0a56c8c3ca7e7a5b8c4d6e", [:mix], [{:hpax, "~> 0.1.1", [hex: :hpax, repo: "hexpm", optional: false]}, {:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}, {:telemetry, "~> 0.4 or ~> 1.0", [hex: :telemetry, repo: "hexpm", optional: false]}, {:thousand_island, "~> 1.0", [hex: :thousand_island, repo: "hexpm", optional: false]}, {:websock, "~> 0.5", [hex: :websock, repo: "hexpm", optional: false]}], "hexpm", "b4c52fd6e97cd2fa9a0a56c8c3ca7e7a5b8c4d6e"},
  "custom_dep": {:git, "git@github.com:company/custom_dep.git", "a1b2c3d4e5f6", []},
  "decimal": {:hex, :decimal, "2.1.1", "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0", [:mix], [], "hexpm", "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1"},
}`)

	packages := r.parseMixLock(mixLock)

	if len(packages) != 3 {
		t.Fatalf("Expected 3 packages, got %d", len(packages))
	}

	// Check bandit
	found := false
	for _, pkg := range packages {
		if pkg.name == "bandit" {
			found = true
			if pkg.version != "1.1.1" {
				t.Errorf("Expected bandit version 1.1.1, got %q", pkg.version)
			}
			if pkg.isGit {
				t.Error("Expected bandit to not be a git dependency")
			}
		}
	}
	if !found {
		t.Error("Expected to find bandit package")
	}

	// Check git dependency
	found = false
	for _, pkg := range packages {
		if pkg.name == "custom_dep" {
			found = true
			if !pkg.isGit {
				t.Error("Expected custom_dep to be a git dependency")
			}
			if pkg.commit != "a1b2c3d4e5f6" {
				t.Errorf("Expected custom_dep commit a1b2c3d4e5f6, got %q", pkg.commit)
			}
		}
	}
	if !found {
		t.Error("Expected to find custom_dep package")
	}
}
