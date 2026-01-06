package graph

import (
	"context"
	"testing"
)

func TestCargoResolver_Ecosystem(t *testing.T) {
	resolver := NewCargoResolver()
	if got := resolver.Ecosystem(); got != "crates.io" {
		t.Errorf("Ecosystem() = %q, want %q", got, "crates.io")
	}
}

func TestCargoResolver_ResolveEdges(t *testing.T) {
	cargoLock := `
[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
  "serde 1.0.188",
  "tokio 1.32.0",
]

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
  "serde_derive 1.0.188",
]

[[package]]
name = "serde_derive"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
  "proc-macro2 1.0.66",
]

[[package]]
name = "proc-macro2"
version = "1.0.66"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.32.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

	cargoToml := `
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.32"
`

	files := &mockFileReader{
		files: map[string][]byte{
			"Cargo.lock": []byte(cargoLock),
			"Cargo.toml": []byte(cargoToml),
		},
	}

	g := New()
	g.AddNode(&Node{
		PURL:      "pkg:cargo/serde@1.0.188",
		Name:      "serde",
		Version:   "1.0.188",
		Ecosystem: "crates.io",
	})
	g.AddNode(&Node{
		PURL:      "pkg:cargo/serde_derive@1.0.188",
		Name:      "serde_derive",
		Version:   "1.0.188",
		Ecosystem: "crates.io",
	})
	g.AddNode(&Node{
		PURL:      "pkg:cargo/proc-macro2@1.0.66",
		Name:      "proc-macro2",
		Version:   "1.0.66",
		Ecosystem: "crates.io",
	})
	g.AddNode(&Node{
		PURL:      "pkg:cargo/tokio@1.32.0",
		Name:      "tokio",
		Version:   "1.32.0",
		Ecosystem: "crates.io",
	})

	resolver := NewCargoResolver()
	err := resolver.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// Check edges were created
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount == 0 {
		t.Error("expected edges to be created, got 0")
	}

	// Verify serde is direct
	serdeNode := g.Node("pkg:cargo/serde@1.0.188")
	if serdeNode == nil {
		t.Fatal("expected serde node to exist")
	}
	if !serdeNode.Direct {
		t.Error("expected serde to be marked as direct")
	}

	// Verify proc-macro2 is transitive
	procNode := g.Node("pkg:cargo/proc-macro2@1.0.66")
	if procNode == nil {
		t.Fatal("expected proc-macro2 node to exist")
	}
	if procNode.Direct {
		t.Error("expected proc-macro2 to NOT be marked as direct")
	}

	// Verify edge exists: serde -> serde_derive
	foundSerdeEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:cargo/serde@1.0.188" && edge.To == "pkg:cargo/serde_derive@1.0.188" {
			foundSerdeEdge = true
			break
		}
	}
	if !foundSerdeEdge {
		t.Error("expected edge from serde to serde_derive")
	}
}

func TestParseCargoDepString(t *testing.T) {
	tests := []struct {
		dep     string
		name    string
		version string
	}{
		{"serde 1.0.188", "serde", "1.0.188"},
		{"tokio 1.32.0 (registry+https://github.com/rust-lang/crates.io-index)", "tokio", "1.32.0"},
		{"proc-macro2 1.0.66", "proc-macro2", "1.0.66"},
		{"rand", "rand", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.dep, func(t *testing.T) {
			name, version := parseCargoDepString(tt.dep)
			if name != tt.name || version != tt.version {
				t.Errorf("parseCargoDepString(%q) = (%q, %q), want (%q, %q)",
					tt.dep, name, version, tt.name, tt.version)
			}
		})
	}
}

func TestCargoPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"serde", "1.0.188", "pkg:cargo/serde@1.0.188"},
		{"tokio", "1.32.0", "pkg:cargo/tokio@1.32.0"},
		{"proc-macro2", "1.0.66", "pkg:cargo/proc-macro2@1.0.66"},
		{"rand", "", "pkg:cargo/rand"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := cargoPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("cargoPkgToPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}
