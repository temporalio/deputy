package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

func TestCollectRowsFromPackages(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	pkgs := []*extractor.Package{
		{
			Name:      "github.com/example/foo",
			Version:   "v1.0.0",
			PURLType:  "golang",
			Licenses:  []string{"MIT"},
			Locations: []string{"go.mod"},
		},
		{
			// duplicate to verify de-duplication
			Name:     "github.com/example/foo",
			Version:  "v1.0.0",
			PURLType: "golang",
		},
		{
			Name:     "requests",
			Version:  "2.31.0",
			PURLType: "pypi",
		},
	}

	rows := collectRowsFromPackages(ctx, "demo-repo", pkgs, func(_ context.Context, pkg *extractor.Package) []string {
		if len(pkg.Licenses) > 0 {
			return pkg.Licenses
		}
		return []string{"Apache-2.0"}
	})

	if got := len(rows["go"]); got != 1 {
		t.Fatalf("expected 1 go row, got %d", got)
	}
	goRow := rows["go"][0]
	if goRow.PackageName != "github.com/example/foo" || goRow.Version != "v1.0.0" {
		t.Fatalf("unexpected go row: %+v", goRow)
	}
	if len(goRow.Licenses) != 1 || goRow.Licenses[0] != "MIT" {
		t.Fatalf("expected MIT license, got %+v", goRow.Licenses)
	}

	if got := len(rows["python"]); got != 1 {
		t.Fatalf("expected 1 python row, got %d", got)
	}
	pyRow := rows["python"][0]
	if pyRow.PackageName != "requests" || pyRow.Licenses[0] != "Apache-2.0" {
		t.Fatalf("unexpected python row: %+v", pyRow)
	}
}

func TestInventoryFromWorkspace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/demo

go 1.22

require github.com/google/uuid v1.6.0
`)
	writeFile(t, filepath.Join(dir, "go.sum"), `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
`)
	writeFile(t, filepath.Join(dir, "main.go"), `package main

import _ "github.com/google/uuid"

func main() {}
`)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	defer ws.Close()

	resolve := func(context.Context, *extractor.Package) []string {
		return []string{"Test-License"}
	}

	rows, err := inventoryFromWorkspace(t.Context(), "demo-repo", ws, []string{"go"}, resolve)
	if err != nil {
		t.Fatalf("inventoryFromWorkspace: %v", err)
	}
	goRows := rows["go"]
	if len(goRows) == 0 {
		t.Fatalf("expected at least one go dependency, got none")
	}
	if !slices.ContainsFunc(goRows, func(row dependencyRow) bool {
		return len(row.Licenses) > 0 && row.Licenses[0] == "Test-License"
	}) {
		t.Fatalf("expected Test-License to be used for dependencies, got %+v", goRows)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func TestCanonicalEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ecosystem string
		purlType  string
		want      string
	}{
		{"docker", "", "container"},
		{"oci", "", "container"},
		{"", "docker", "container"},
		{"", "oci", "container"},
		{"githubactions", "", "githubactions"},
		{"GitHub Actions", "", "githubactions"},
		{"gha", "", "githubactions"},
		{"go", "", "go"},
		{"golang", "", "go"},
		{"npm", "", "javascript"},
		{"pypi", "", "python"},
	}

	for _, tt := range tests {
		pkg := &extractor.Package{PURLType: tt.purlType}
		// Set ecosystem via reflection since Ecosystem() returns p.PURLType
		if tt.ecosystem != "" {
			pkg.PURLType = tt.ecosystem
		}
		got := canonicalEcosystem(pkg)
		if got != tt.want {
			t.Errorf("canonicalEcosystem(%q/%q) = %q, want %q", tt.ecosystem, tt.purlType, got, tt.want)
		}
	}
}

func TestLookupContainerLicense(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    []string
	}{
		// Docker Hub library images (library/ prefix)
		{"library/alpine", "3.19", []string{"MIT"}},
		{"library/golang", "1.22", []string{"BSD-3-Clause"}},
		{"library/python", "3.12", []string{"PSF-2.0"}},
		{"library/nginx", "1.25", []string{"BSD-2-Clause"}},
		{"library/ubuntu", "24.04", []string{"GPL-2.0"}},
		{"library/debian", "bookworm", []string{"GPL-2.0"}},
		{"library/busybox", "1.36", []string{"GPL-2.0"}},

		// Google distroless images
		{"gcr.io/distroless/static", "nonroot", []string{"Apache-2.0"}},
		{"gcr.io/distroless/base", "latest", []string{"Apache-2.0"}},
		{"gcr.io/distroless/static-debian11", "nonroot", []string{"Apache-2.0"}},

		// Chainguard images
		{"cgr.dev/chainguard/static", "latest", []string{"Apache-2.0"}},
		{"cgr.dev/chainguard/go", "latest", []string{"Apache-2.0"}},
		{"cgr.dev/chainguard/glibc-dynamic", "latest", []string{"Apache-2.0"}},

		// Microsoft .NET images
		{"mcr.microsoft.com/dotnet/sdk", "8.0", []string{"MIT"}},

		// Database images
		{"library/postgres", "16", []string{"PostgreSQL"}},
		{"library/redis", "7", []string{"BSD-3-Clause"}},

		// Third-party registry images
		{"ghcr.io/astral-sh/uv", "latest", []string{"MIT", "Apache-2.0"}},
		{"grafana/grafana", "latest", []string{"AGPL-3.0"}},

		// Images with version suffixes like -slim, -alpine
		{"library/python", "3.12-slim", []string{"PSF-2.0"}},
		{"library/golang", "1.22-alpine", []string{"BSD-3-Clause"}},

		// Unknown images should return nil
		{"some-unknown-registry.io/custom/image", "1.0", nil},
		{"internal-registry/private-image", "latest", nil},
	}

	for _, tt := range tests {
		got := lookupContainerLicense(tt.name, tt.version)
		if !slices.Equal(got, tt.want) {
			t.Errorf("lookupContainerLicense(%q, %q) = %v, want %v", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestShouldSkipUnresolvable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ecosystem string
		name      string
		version   string
		want      bool
	}{
		// Container: variable placeholders should be skipped
		{"container", "${SOURCE_IMAGE}", "latest", true},
		{"container", "${BOSS_PROXY_IMAGE}", "1.0", true},
		{"container", "${{github.event.inputs.image}}", "latest", true},

		// Container: internal build artifacts should be skipped
		{"container", "library/oss_server_src_image", "latest", true},
		{"container", "library/sdk_python_src_image", "latest", true},
		{"container", "my-builder-fresh", "latest", true},

		// Container: normal images should not be skipped
		{"container", "library/alpine", "3.19", false},
		{"container", "gcr.io/distroless/static", "nonroot", false},
		{"container", "ghcr.io/astral-sh/uv", "latest", false},

		// GitHub Actions: normal actions should not be skipped
		{"githubactions", "actions/checkout", "v4", false},
		{"githubactions", "docker/login-action", "v3", false},

		// Other ecosystems should not be filtered
		{"go", "github.com/example/pkg", "v1.0.0", false},
		{"javascript", "lodash", "4.17.21", false},
	}

	for _, tt := range tests {
		got := shouldSkipUnresolvable(tt.ecosystem, tt.name, tt.version)
		if got != tt.want {
			t.Errorf("shouldSkipUnresolvable(%q, %q, %q) = %v, want %v",
				tt.ecosystem, tt.name, tt.version, got, tt.want)
		}
	}
}

func TestLooksLikeSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		// Full SHA (40 hex chars)
		{"b62528385c34dbc9f38e5f4225ac829252d1ea92", true},
		{"f054a8b539a109f9f41c372932f1ae047eff08c9", true},
		{"ABCDEF1234567890abcdef1234567890ABCDEF12", true},

		// Not full SHA
		{"v4", false},
		{"v2.0.0", false},
		{"main", false},
		{"master", false},
		{"b62528385c34dbc9f38e5f4225ac829252d1ea9", false},   // 39 chars
		{"b62528385c34dbc9f38e5f4225ac829252d1ea921", false}, // 41 chars
		{"g62528385c34dbc9f38e5f4225ac829252d1ea92", false},  // non-hex char
	}

	for _, tt := range tests {
		got := looksLikeSHA(tt.input)
		if got != tt.want {
			t.Errorf("looksLikeSHA(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLooksLikeShortSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		// Short SHA (7+ hex chars, no dots)
		{"b625283", true},
		{"f054a8b539a109f9f41c3729", true},
		{"abcdef1", true},

		// Not short SHA
		{"v4", false},          // starts with v + digit
		{"v2.0.0", false},      // version with dots
		{"1.2.3", false},       // has dots
		{"abc", false},         // too short
		{"abcdefg", false},     // has 'g' (non-hex)
		{"main", false},        // has non-hex
		{"releases/v1", false}, // has slash
	}

	for _, tt := range tests {
		got := looksLikeShortSHA(tt.input)
		if got != tt.want {
			t.Errorf("looksLikeShortSHA(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeGitHubActionVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		// Normal version tags should pass through
		{"v4", "v4"},
		{"v2.0.0", "v2.0.0"},
		{"v1.2.3", "v1.2.3"},

		// Full SHA should return empty (trigger default branch)
		{"b62528385c34dbc9f38e5f4225ac829252d1ea92", ""},
		{"f054a8b539a109f9f41c372932f1ae047eff08c9", ""},

		// Short SHA should return empty
		{"b625283", ""},
		{"f054a8b539a109f9", ""},

		// Branch names should pass through
		{"main", "main"},
		{"master", "master"},
		{"releases/v1", "releases/v1"},

		// Empty should stay empty
		{"", ""},
	}

	for _, tt := range tests {
		got := normalizeGitHubActionVersion(tt.input)
		if got != tt.want {
			t.Errorf("normalizeGitHubActionVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuildImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    string
	}{
		// Docker Hub official images
		{"alpine", "3.19", "index.docker.io/library/alpine:3.19"},
		{"nginx", "latest", "index.docker.io/library/nginx:latest"},
		{"library/golang", "1.22", "index.docker.io/library/golang:1.22"},
		{"python", "", "index.docker.io/library/python:latest"},

		// Docker Hub user images
		{"grafana/grafana", "10.0", "index.docker.io/grafana/grafana:10.0"},
		{"bitnami/redis", "7.0", "index.docker.io/bitnami/redis:7.0"},

		// Third-party registries (already have dots in first segment)
		{"ghcr.io/astral-sh/uv", "latest", "ghcr.io/astral-sh/uv:latest"},
		{"gcr.io/distroless/static", "nonroot", "gcr.io/distroless/static:nonroot"},
		{"quay.io/prometheus/node-exporter", "v1.7.0", "quay.io/prometheus/node-exporter:v1.7.0"},

		// Digest references
		{"alpine", "sha256:abc123", "index.docker.io/library/alpine@sha256:abc123"},
		{"ghcr.io/owner/repo", "sha256:def456", "ghcr.io/owner/repo@sha256:def456"},

		// Already has tag in name
		{"nginx:1.25", "ignored", "nginx:1.25"},
		{"gcr.io/project/image:v1", "ignored", "gcr.io/project/image:v1"},

		// Already has digest in name
		{"nginx@sha256:abc", "ignored", "nginx@sha256:abc"},
	}

	for _, tt := range tests {
		got := buildImageReference(tt.name, tt.version)
		if got != tt.want {
			t.Errorf("buildImageReference(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestParseOCILicenseExpression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  []string
	}{
		// Single license
		{"MIT", []string{"MIT"}},
		{"Apache-2.0", []string{"Apache-2.0"}},
		{"GPL-3.0-only", []string{"GPL-3.0-only"}},

		// SPDX OR expression
		{"MIT OR Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"GPL-2.0 OR GPL-3.0", []string{"GPL-2.0", "GPL-3.0"}},

		// SPDX AND expression
		{"MIT AND Apache-2.0", []string{"Apache-2.0", "MIT"}},

		// Mixed case operators
		{"MIT or Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"MIT and GPL-2.0", []string{"GPL-2.0", "MIT"}},

		// Comma-separated (non-standard but common)
		{"MIT, Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"MIT; Apache-2.0", []string{"Apache-2.0", "MIT"}},

		// With parentheses (complex expressions)
		{"(MIT OR Apache-2.0)", []string{"Apache-2.0", "MIT"}},
		{"(MIT AND GPL-2.0) OR Apache-2.0", []string{"Apache-2.0", "GPL-2.0", "MIT"}},

		// Duplicates should be removed
		{"MIT OR MIT", []string{"MIT"}},
		{"Apache-2.0, Apache-2.0", []string{"Apache-2.0"}},

		// Empty/whitespace
		{"", nil},
		{"  ", nil},

		// Real-world examples from container images
		{"Apache-2.0", []string{"Apache-2.0"}},
		{"BSD-3-Clause", []string{"BSD-3-Clause"}},
		{"MIT AND Apache-2.0", []string{"Apache-2.0", "MIT"}},
	}

	for _, tt := range tests {
		got := parseOCILicenseExpression(tt.input)
		if !slices.Equal(got, tt.want) {
			t.Errorf("parseOCILicenseExpression(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
