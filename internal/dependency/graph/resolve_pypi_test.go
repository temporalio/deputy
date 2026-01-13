package graph

import (
	"context"
	"testing"
)

func TestPyPIResolver_Ecosystem(t *testing.T) {
	resolver := NewPyPIResolver()
	if got := resolver.Ecosystem(); got != "PyPI" {
		t.Errorf("Ecosystem() = %q, want %q", got, "PyPI")
	}
}

func TestPyPIResolver_PoetryLock(t *testing.T) {
	poetryLock := `
[[package]]
name = "requests"
version = "2.28.2"
category = "main"

[package.dependencies]
urllib3 = ">=1.21.1,<3"
certifi = ">=2017.4.17"

[[package]]
name = "urllib3"
version = "2.0.4"
category = "main"

[[package]]
name = "certifi"
version = "2023.7.22"
category = "main"
`

	pyprojectToml := `
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
`

	files := &mockFileReader{
		files: map[string][]byte{
			"poetry.lock":     []byte(poetryLock),
			"pyproject.toml":  []byte(pyprojectToml),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:pypi/requests@2.28.2",
		Name:      "requests",
		Version:   "2.28.2",
		Ecosystem: "PyPI",
	})
	g.AddNode(&Node{
		Purl:      "pkg:pypi/urllib3@2.0.4",
		Name:      "urllib3",
		Version:   "2.0.4",
		Ecosystem: "PyPI",
	})
	g.AddNode(&Node{
		Purl:      "pkg:pypi/certifi@2023.7.22",
		Name:      "certifi",
		Version:   "2023.7.22",
		Ecosystem: "PyPI",
	})

	resolver := NewPyPIResolver()
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

	// Verify requests is direct
	requestsNode := g.Node("pkg:pypi/requests@2.28.2")
	if requestsNode == nil {
		t.Fatal("expected requests node to exist")
	}
	if !requestsNode.Direct {
		t.Error("expected requests to be marked as direct")
	}

	// Verify urllib3 is transitive
	urllib3Node := g.Node("pkg:pypi/urllib3@2.0.4")
	if urllib3Node == nil {
		t.Fatal("expected urllib3 node to exist")
	}
	if urllib3Node.Direct {
		t.Error("expected urllib3 to NOT be marked as direct")
	}

	// Verify edge exists: requests -> urllib3
	foundEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:pypi/requests@2.28.2" && edge.To == "pkg:pypi/urllib3@2.0.4" {
			foundEdge = true
			break
		}
	}
	if !foundEdge {
		t.Error("expected edge from requests to urllib3")
	}
}

func TestPyPIResolver_RequirementsTxt(t *testing.T) {
	requirements := `
# This is a comment
requests==2.28.2
flask>=2.0.0
django[bcrypt]>=4.0

# Development dependencies
pytest>=7.0.0
-e .
`

	files := &mockFileReader{
		files: map[string][]byte{
			"requirements.txt": []byte(requirements),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:pypi/requests@2.28.2",
		Name:      "requests",
		Version:   "2.28.2",
		Ecosystem: "PyPI",
	})
	g.AddNode(&Node{
		Purl:      "pkg:pypi/flask@2.0.0",
		Name:      "flask",
		Version:   "2.0.0",
		Ecosystem: "PyPI",
	})

	resolver := NewPyPIResolver()
	err := resolver.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// All requirements.txt entries should be direct
	requestsNode := g.Node("pkg:pypi/requests@2.28.2")
	if requestsNode == nil {
		t.Fatal("expected requests node to exist")
	}
	if !requestsNode.Direct {
		t.Error("expected requests to be marked as direct")
	}
}

func TestParseRequirementsLine(t *testing.T) {
	tests := []struct {
		line    string
		name    string
		version string
	}{
		{"requests==2.28.2", "requests", "2.28.2"},
		{"flask>=2.0.0", "flask", ""},
		{"django[bcrypt]>=4.0", "django", ""},
		{"pytest==7.0.0; python_version >= '3.7'", "pytest", "7.0.0"},
		{"numpy>=1.0,<2.0", "numpy", ""},
		{"# comment", "", ""},
		{"", "", ""},
		{"-e .", "", ""},
		{"package-name==1.0.0", "package-name", "1.0.0"},
		{"Package_Name==1.0.0", "Package_Name", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, version := parseRequirementsLine(tt.line)
			if name != tt.name || version != tt.version {
				t.Errorf("parseRequirementsLine(%q) = (%q, %q), want (%q, %q)",
					tt.line, name, version, tt.name, tt.version)
			}
		})
	}
}

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"requests", "requests"},
		{"Requests", "requests"},
		{"REQUESTS", "requests"},
		{"package_name", "package-name"},
		{"package.name", "package-name"},
		{"Package_Name", "package-name"},
		{"Django", "django"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePyPIName(tt.input)
			if got != tt.want {
				t.Errorf("normalizePyPIName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPypiPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"requests", "2.28.2", "pkg:pypi/requests@2.28.2"},
		{"Flask", "2.0.0", "pkg:pypi/flask@2.0.0"},
		{"package_name", "1.0.0", "pkg:pypi/package-name@1.0.0"},
		{"Django", "", "pkg:pypi/django"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := pypiPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("pypiPkgToPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}

func TestExtractPyPINameFromSpec(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"requests>=2.0", "requests"},
		{"flask>=2.0,<3.0", "flask"},
		{"django[bcrypt]>=4.0", "django"},
		{"pytest", "pytest"},
		{"numpy==1.0.0", "numpy"},
		{"package-name>=1.0", "package-name"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got := extractPyPINameFromSpec(tt.spec)
			if got != tt.want {
				t.Errorf("extractPyPINameFromSpec(%q) = %q, want %q", tt.spec, got, tt.want)
			}
		})
	}
}
