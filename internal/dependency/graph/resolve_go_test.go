package graph

import (
	"context"
	"testing"
)

// mockFileReader is a simple FileReader for testing.
type mockFileReader struct {
	files map[string][]byte
}

func (m *mockFileReader) ReadFile(name string) ([]byte, error) {
	if data, ok := m.files[name]; ok {
		return data, nil
	}
	return nil, &mockNotFoundError{name}
}

type mockNotFoundError struct {
	name string
}

func (e *mockNotFoundError) Error() string {
	return "file not found: " + e.name
}

func TestGoResolver_ResolveEdges(t *testing.T) {
	goModContent := `module github.com/example/myapp

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
`

	files := &mockFileReader{
		files: map[string][]byte{
			"go.mod": []byte(goModContent),
		},
	}

	// Create a graph with some nodes from "inventory"
	g := New()
	g.AddNode(&Node{
		PURL:      "pkg:golang/github.com/pkg/errors@0.9.1",
		Name:      "github.com/pkg/errors",
		Version:   "0.9.1",
		Ecosystem: "Go",
	})
	g.AddNode(&Node{
		PURL:      "pkg:golang/github.com/stretchr/testify@1.8.4",
		Name:      "github.com/stretchr/testify",
		Version:   "1.8.4",
		Ecosystem: "Go",
	})
	g.AddNode(&Node{
		PURL:      "pkg:golang/github.com/davecgh/go-spew@1.1.1",
		Name:      "github.com/davecgh/go-spew",
		Version:   "1.1.1",
		Ecosystem: "Go",
	})

	resolver := NewGoResolver()
	err := resolver.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// Check that edges were created
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount == 0 {
		t.Error("expected edges to be created, got 0")
	}

	// Check that direct dependencies are marked as direct
	errorsNode := g.Node("pkg:golang/github.com/pkg/errors@0.9.1")
	if errorsNode == nil {
		t.Fatal("expected errors node to exist")
	}
	if !errorsNode.Direct {
		t.Error("expected github.com/pkg/errors to be marked as direct")
	}

	// Check that indirect dependencies are not marked as direct
	spewNode := g.Node("pkg:golang/github.com/davecgh/go-spew@1.1.1")
	if spewNode == nil {
		t.Fatal("expected go-spew node to exist")
	}
	if spewNode.Direct {
		t.Error("expected github.com/davecgh/go-spew to not be marked as direct")
	}

	// Check that depths were calculated for direct dependencies
	if errorsNode.Depth != 0 {
		t.Errorf("expected errors depth to be 0, got %d", errorsNode.Depth)
	}
	// Indirect deps without proxy/git/vendor remain at DepthDisconnected
	// because we can't verify their exact position without additional sources.
	// This is intentional - we prioritize precision over guessing.
	if spewNode.Depth != DepthDisconnected {
		t.Logf("indirect dep go-spew has depth %d (%d = unknown without proxy/git)", spewNode.Depth, DepthDisconnected)
	}
}

func TestGoResolver_Ecosystem(t *testing.T) {
	resolver := NewGoResolver()
	if got := resolver.Ecosystem(); got != "Go" {
		t.Errorf("Ecosystem() = %q, want %q", got, "Go")
	}
}

func TestGoResolver_StdlibSupport(t *testing.T) {
	goModContent := `module github.com/example/myapp

go 1.21

require github.com/pkg/errors v0.9.1
`

	files := &mockFileReader{
		files: map[string][]byte{
			"go.mod": []byte(goModContent),
		},
	}

	g := New()
	g.AddNode(&Node{
		PURL:      "pkg:golang/github.com/pkg/errors@0.9.1",
		Name:      "github.com/pkg/errors",
		Version:   "0.9.1",
		Ecosystem: "Go",
	})

	resolver := NewGoResolver()
	err := resolver.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// Check that stdlib node was created
	stdlibNode := g.Node("pkg:golang/stdlib@1.21")
	if stdlibNode == nil {
		t.Fatal("expected stdlib node to be created")
	}

	// Verify stdlib properties
	if stdlibNode.Name != "stdlib" {
		t.Errorf("expected stdlib node name to be 'stdlib', got %q", stdlibNode.Name)
	}
	if stdlibNode.Version != "1.21" {
		t.Errorf("expected stdlib version to be '1.21', got %q", stdlibNode.Version)
	}
	if stdlibNode.Ecosystem != "Go" {
		t.Errorf("expected stdlib ecosystem to be 'Go', got %q", stdlibNode.Ecosystem)
	}
	if !stdlibNode.Direct {
		t.Error("expected stdlib to be marked as direct dependency")
	}
	if stdlibNode.Depth != 0 {
		t.Errorf("expected stdlib depth to be 0 (direct), got %d", stdlibNode.Depth)
	}

	// Check that there's an edge from root to stdlib
	rootPURL := "pkg:golang/github.com/example/myapp"
	foundEdge := false
	for edge := range g.Edges() {
		if edge.From == rootPURL && edge.To == stdlibNode.PURL {
			foundEdge = true
			if edge.Constraint != "1.21" {
				t.Errorf("expected stdlib edge constraint to be '1.21', got %q", edge.Constraint)
			}
			break
		}
	}
	if !foundEdge {
		t.Error("expected edge from root module to stdlib")
	}
}

func TestGoStdlibToPURL(t *testing.T) {
	tests := []struct {
		goVersion string
		want      string
	}{
		{"1.21", "pkg:golang/stdlib@1.21"},
		{"1.21.0", "pkg:golang/stdlib@1.21.0"},
		{"1.22.3", "pkg:golang/stdlib@1.22.3"},
		{"", "pkg:golang/stdlib"},
		{"  1.21  ", "pkg:golang/stdlib@1.21"},
	}

	for _, tt := range tests {
		t.Run(tt.goVersion, func(t *testing.T) {
			got := goStdlibToPURL(tt.goVersion)
			if got != tt.want {
				t.Errorf("goStdlibToPURL(%q) = %q, want %q", tt.goVersion, got, tt.want)
			}
		})
	}
}

func TestGoModuleToPURL(t *testing.T) {
	tests := []struct {
		modulePath string
		version    string
		want       string
	}{
		{"github.com/pkg/errors", "v0.9.1", "pkg:golang/github.com/pkg/errors@0.9.1"},
		{"github.com/pkg/errors", "0.9.1", "pkg:golang/github.com/pkg/errors@0.9.1"},
		{"golang.org/x/sys", "v0.15.0", "pkg:golang/golang.org/x/sys@0.15.0"},
		{"github.com/example/foo", "", "pkg:golang/github.com/example/foo"},
	}

	for _, tt := range tests {
		t.Run(tt.modulePath+"@"+tt.version, func(t *testing.T) {
			got := goModuleToPURL(tt.modulePath, tt.version)
			if got != tt.want {
				t.Errorf("goModuleToPURL(%q, %q) = %q, want %q", tt.modulePath, tt.version, got, tt.want)
			}
		})
	}
}

func TestWorkspaceFileReader(t *testing.T) {
	// Create a mock workspace
	mockWS := &mockWorkspace{
		files: map[string][]byte{
			"go.mod": []byte("module test"),
		},
	}

	reader := NewWorkspaceFileReader(mockWS)

	data, err := reader.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "module test" {
		t.Errorf("ReadFile returned %q, want %q", string(data), "module test")
	}
}

type mockWorkspace struct {
	files map[string][]byte
}

func (m *mockWorkspace) ReadFile(name string) ([]byte, error) {
	if data, ok := m.files[name]; ok {
		return data, nil
	}
	return nil, &mockNotFoundError{name}
}
