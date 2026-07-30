package graph

import (
	"testing"
)

func TestNpmResolver_Ecosystem(t *testing.T) {
	resolver := NewNpmResolver()
	if got := resolver.Ecosystem(); got != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", got, "npm")
	}
}

func TestNpmResolver_ResolveEdges_PackageLockV3(t *testing.T) {
	// Modern package-lock.json v3 format with "packages" field
	packageLock := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": "1.20.1"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.1",
      "dependencies": {
        "bytes": "3.1.2"
      }
    },
    "node_modules/bytes": {
      "version": "3.1.2"
    }
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"package-lock.json": []byte(packageLock),
		},
	}

	// Create a graph with some nodes from "inventory"
	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:npm/express@4.18.2",
		Name:      "express",
		Version:   "4.18.2",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/body-parser@1.20.1",
		Name:      "body-parser",
		Version:   "1.20.1",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/bytes@3.1.2",
		Name:      "bytes",
		Version:   "3.1.2",
		Ecosystem: "npm",
	})

	resolver := NewNpmResolver()
	err := resolver.ResolveEdges(t.Context(), g, files)
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

	// Verify express is marked as direct
	expressNode := g.Node("pkg:npm/express@4.18.2")
	if expressNode == nil {
		t.Fatal("expected express node to exist")
	}
	if !expressNode.Direct {
		t.Error("expected express to be marked as direct")
	}

	// Verify bytes is NOT marked as direct (transitive)
	bytesNode := g.Node("pkg:npm/bytes@3.1.2")
	if bytesNode == nil {
		t.Fatal("expected bytes node to exist")
	}
	if bytesNode.Direct {
		t.Error("expected bytes to NOT be marked as direct")
	}
}

func TestNpmResolver_ResolveEdges_PackageLockV1(t *testing.T) {
	// Legacy package-lock.json v1 format with "dependencies" field
	packageLock := `{
  "name": "legacy-project",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "requires": {
      }
    },
    "axios": {
      "version": "1.4.0",
      "requires": {
        "follow-redirects": "^1.15.0"
      }
    },
    "follow-redirects": {
      "version": "1.15.2"
    }
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"package-lock.json": []byte(packageLock),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:npm/lodash@4.17.21",
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/axios@1.4.0",
		Name:      "axios",
		Version:   "1.4.0",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/follow-redirects@1.15.2",
		Name:      "follow-redirects",
		Version:   "1.15.2",
		Ecosystem: "npm",
	})

	resolver := NewNpmResolver()
	err := resolver.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// Check that lodash is direct
	lodashNode := g.Node("pkg:npm/lodash@4.17.21")
	if lodashNode == nil {
		t.Fatal("expected lodash node to exist")
	}
	if !lodashNode.Direct {
		t.Error("expected lodash to be marked as direct")
	}

	// Check axios is direct
	axiosNode := g.Node("pkg:npm/axios@1.4.0")
	if axiosNode == nil {
		t.Fatal("expected axios node to exist")
	}
	if !axiosNode.Direct {
		t.Error("expected axios to be marked as direct")
	}
}

func TestNpmResolver_ScopedPackages(t *testing.T) {
	// Test scoped packages like @types/node
	packageLock := `{
  "name": "typed-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "typed-project",
      "version": "1.0.0",
      "devDependencies": {
        "@types/node": "^18.0.0"
      }
    },
    "node_modules/@types/node": {
      "version": "18.15.0",
      "dev": true
    }
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"package-lock.json": []byte(packageLock),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:npm/@types/node@18.15.0",
		Name:      "@types/node",
		Version:   "18.15.0",
		Ecosystem: "npm",
	})

	resolver := NewNpmResolver()
	err := resolver.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	typesNode := g.Node("pkg:npm/@types/node@18.15.0")
	if typesNode == nil {
		t.Fatal("expected @types/node node to exist")
	}
	if !typesNode.Direct {
		t.Error("expected @types/node to be marked as direct")
	}
}

func TestExtractNpmPackageName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/express/node_modules/debug", "debug"},
		{"node_modules/@babel/core/node_modules/@babel/helper-module-transforms", "@babel/helper-module-transforms"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractNpmPackageName(tt.path)
			if got != tt.want {
				t.Errorf("extractNpmPackageName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsDirectNpmDep(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"node_modules/lodash", true},
		{"node_modules/@types/node", true},
		{"node_modules/express/node_modules/debug", false},
		{"node_modules/@babel/core/node_modules/semver", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isDirectNpmDep(tt.path)
			if got != tt.want {
				t.Errorf("isDirectNpmDep(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestNpmPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"@types/node", "18.15.0", "pkg:npm/@types/node@18.15.0"},
		{"express", "", "pkg:npm/express"},
		{"@babel/core", "7.20.0", "pkg:npm/@babel/core@7.20.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := npmPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("npmPkgToPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}

// ============================================================================
// yarn.lock tests
// ============================================================================

func TestNpmResolver_ResolveEdges_YarnLockV1(t *testing.T) {
	// yarn.lock v1 format
	yarnLock := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

concat-map@0.0.1:
  version "0.0.1"
  resolved "https://registry.yarnpkg.com/concat-map/-/concat-map-0.0.1.tgz"
  integrity sha1-2Klr13/Wjfd5OnMDajug1UBdR3s=

concat-stream@^1.5.0:
  version "1.6.2"
  resolved "https://registry.npmjs.org/concat-stream/-/concat-stream-1.6.2.tgz"
  integrity sha512-27HBghJxjiZtIk3Ycvn/4kbJk/1uZuJFfuPEns6LaEvpvG1f0hTea8lilrouyo9mVc2GWdcEZ8OLoGmSADlrCw==
  dependencies:
    buffer-from "^1.0.0"
    inherits "^2.0.3"

buffer-from@^1.0.0:
  version "1.1.2"
  resolved "https://registry.yarnpkg.com/buffer-from/-/buffer-from-1.1.2.tgz"

inherits@^2.0.3:
  version "2.0.4"
  resolved "https://registry.yarnpkg.com/inherits/-/inherits-2.0.4.tgz"
`

	packageJSON := `{
  "name": "test-yarn-project",
  "version": "1.0.0",
  "dependencies": {
    "concat-stream": "^1.5.0"
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"yarn.lock":    []byte(yarnLock),
			"package.json": []byte(packageJSON),
		},
	}

	g := New()
	// Pre-populate with nodes from "inventory"
	g.AddNode(&Node{
		Purl:      "pkg:npm/concat-stream@1.6.2",
		Name:      "concat-stream",
		Version:   "1.6.2",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/buffer-from@1.1.2",
		Name:      "buffer-from",
		Version:   "1.1.2",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/inherits@2.0.4",
		Name:      "inherits",
		Version:   "2.0.4",
		Ecosystem: "npm",
	})

	resolver := NewNpmResolver()
	err := resolver.ResolveEdges(t.Context(), g, files)
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

	// Verify concat-stream is marked as direct
	concatNode := g.Node("pkg:npm/concat-stream@1.6.2")
	if concatNode == nil {
		t.Fatal("expected concat-stream node to exist")
	}
	if !concatNode.Direct {
		t.Error("expected concat-stream to be marked as direct")
	}

	// Verify buffer-from is NOT direct (transitive dep of concat-stream)
	bufferNode := g.Node("pkg:npm/buffer-from@1.1.2")
	if bufferNode == nil {
		t.Fatal("expected buffer-from node to exist")
	}
	if bufferNode.Direct {
		t.Error("expected buffer-from to NOT be marked as direct")
	}

	// Verify edge from concat-stream to buffer-from
	hasEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:npm/concat-stream@1.6.2" && edge.To == "pkg:npm/buffer-from@1.1.2" {
			hasEdge = true
			break
		}
	}
	if !hasEdge {
		t.Error("expected edge from concat-stream to buffer-from")
	}
}

func TestExtractYarnPackageName(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{`"lodash@^4.17.0":`, "lodash"},
		{`"@types/node@^18.0.0":`, "@types/node"},
		{`"@babel/core@^7.0.0", "@babel/core@^7.12.0":`, "@babel/core"},
		{`concat-map@0.0.1:`, "concat-map"},
		// npm: alias keeps the original scoped name
		{`"@nicolo-ribaudo/chokidar-2@npm:2.1.8":`, "@nicolo-ribaudo/chokidar-2"},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := extractYarnPackageName(tt.header)
			if got != tt.want {
				t.Errorf("extractYarnPackageName(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestParseYarnLock(t *testing.T) {
	yarnLock := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

express@^4.18.0:
  version "4.18.2"
  dependencies:
    body-parser "1.20.1"
    cookie "0.5.0"

body-parser@1.20.1:
  version "1.20.1"
`

	entries, err := parseYarnLock([]byte(yarnLock))
	if err != nil {
		t.Fatalf("parseYarnLock failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	// Check lodash entry
	found := false
	for _, e := range entries {
		if e.name == "lodash" {
			found = true
			if e.version != "4.17.21" {
				t.Errorf("lodash version = %q, want %q", e.version, "4.17.21")
			}
		}
	}
	if !found {
		t.Error("expected to find lodash entry")
	}

	// Check express has dependencies
	for _, e := range entries {
		if e.name == "express" {
			if len(e.dependencies) != 2 {
				t.Errorf("express dependencies count = %d, want 2", len(e.dependencies))
			}
			if e.dependencies["body-parser"] != "1.20.1" {
				t.Errorf("express dep body-parser = %q, want %q", e.dependencies["body-parser"], "1.20.1")
			}
		}
	}
}

// ============================================================================
// pnpm-lock.yaml tests
// ============================================================================

func TestNpmResolver_ResolveEdges_PnpmLock(t *testing.T) {
	// pnpm-lock.yaml v5.3 format
	pnpmLock := `lockfileVersion: 5.3

specifiers:
  acorn: ^8.7.0

dependencies:
  acorn: 8.7.0

packages:

  /acorn/8.7.0:
    resolution: {integrity: sha512-abc==}
    engines: {node: '>=0.4.0'}
    hasBin: true
    dev: false

  /acorn-jsx/5.3.2:
    resolution: {integrity: sha512-def==}
    dependencies:
      acorn: 8.7.0
    dev: false
`

	packageJSON := `{
  "name": "test-pnpm-project",
  "version": "1.0.0",
  "dependencies": {
    "acorn": "^8.7.0"
  }
}`

	files := &mockFileReader{
		files: map[string][]byte{
			"pnpm-lock.yaml": []byte(pnpmLock),
			"package.json":   []byte(packageJSON),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:npm/acorn@8.7.0",
		Name:      "acorn",
		Version:   "8.7.0",
		Ecosystem: "npm",
	})
	g.AddNode(&Node{
		Purl:      "pkg:npm/acorn-jsx@5.3.2",
		Name:      "acorn-jsx",
		Version:   "5.3.2",
		Ecosystem: "npm",
	})

	resolver := NewNpmResolver()
	err := resolver.ResolveEdges(t.Context(), g, files)
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

	// Verify acorn is marked as direct
	acornNode := g.Node("pkg:npm/acorn@8.7.0")
	if acornNode == nil {
		t.Fatal("expected acorn node to exist")
	}
	if !acornNode.Direct {
		t.Error("expected acorn to be marked as direct")
	}

	// Verify edge from acorn-jsx to acorn
	hasEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:npm/acorn-jsx@5.3.2" && edge.To == "pkg:npm/acorn@8.7.0" {
			hasEdge = true
			break
		}
	}
	if !hasEdge {
		t.Error("expected edge from acorn-jsx to acorn")
	}
}

func TestExtractPnpmPackageNameVersion(t *testing.T) {
	tests := []struct {
		pkgPath     string
		lockVersion float64
		pkg         pnpmLockPackage
		wantName    string
		wantVersion string
	}{
		// v5 format
		{"/lodash/4.17.21", 5.3, pnpmLockPackage{}, "lodash", "4.17.21"},
		{"/@types/node/18.15.0", 5.3, pnpmLockPackage{}, "@types/node", "18.15.0"},
		{"/acorn-jsx/5.3.2_acorn@8.7.0", 5.3, pnpmLockPackage{}, "acorn-jsx", "5.3.2"},

		// v9 format
		{"'lodash@4.17.21'", 9.0, pnpmLockPackage{}, "lodash", "4.17.21"},
		{"'@types/node@18.15.0'", 9.0, pnpmLockPackage{}, "@types/node", "18.15.0"},

		// Explicit name/version in package
		{"/whatever/path", 5.3, pnpmLockPackage{Name: "explicit-name", Version: "1.0.0"}, "explicit-name", "1.0.0"},

		// Skip file: deps
		{"file:local-pkg", 5.3, pnpmLockPackage{}, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkgPath, func(t *testing.T) {
			gotName, gotVersion := extractPnpmPackageNameVersion(tt.pkgPath, tt.lockVersion, tt.pkg)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("extractPnpmPackageNameVersion(%q, %v) = (%q, %q), want (%q, %q)",
					tt.pkgPath, tt.lockVersion, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParsePnpmLockVersion(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"5.3", 5.3},
		{"'5.4'", 5.4},
		{`"6.0"`, 6.0},
		{"9.0", 9.0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePnpmLockVersion(tt.input)
			if got != tt.want {
				t.Errorf("parsePnpmLockVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
