package dockerfilex

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"DOCKERFILE", true},
		{"Containerfile", true},
		{"containerfile", true},
		{"server.Dockerfile", true},
		{"server.dockerfile", true},
		{"admin-tools.Dockerfile", true},
		{"build.containerfile", true},
		{"targets/server.Dockerfile", true},
		{"docker/Dockerfile", true},
		{"docker/Dockerfile.prod", false}, // prefix, not suffix
		{"README.md", false},
		{"go.mod", false},
		{"main.go", false},
		{".github/workflows/ci.yml", false},
	}

	ext := New()
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := &mockFileAPI{path: tt.path}
			got := ext.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

type mockFileAPI struct {
	path string
}

func (m *mockFileAPI) Path() string { return m.path }

func (m *mockFileAPI) Stat() (fs.FileInfo, error) {
	return &mockFileInfo{name: m.path}, nil
}

type mockFileInfo struct {
	name string
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() any           { return nil }

func TestExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantPkgs []struct {
			name     string
			version  string
			purlType string
		}
	}{
		{
			name: "simple alpine",
			content: `FROM alpine:3.19
RUN apk add --no-cache curl
`,
			wantPkgs: []struct {
				name     string
				version  string
				purlType string
			}{
				// Official Docker Hub images are normalized to library/name
				{"library/alpine", "3.19", purl.TypeDocker},
			},
		},
		{
			name: "multi-stage build",
			content: `FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app/app /usr/local/bin/
CMD ["/usr/local/bin/app"]
`,
			wantPkgs: []struct {
				name     string
				version  string
				purlType string
			}{
				// Official Docker Hub images are normalized to library/name
				{"library/golang", "1.21", purl.TypeDocker},
				{"library/alpine", "3.19", purl.TypeDocker},
			},
		},
		{
			name: "non-docker-hub registry",
			content: `FROM gcr.io/distroless/static:nonroot
COPY app /app
CMD ["/app"]
`,
			wantPkgs: []struct {
				name     string
				version  string
				purlType string
			}{
				// Non-Docker Hub registries use pkg:oci and include the registry
				{"gcr.io/distroless/static", "nonroot", purl.TypeOCI},
			},
		},
		{
			name: "scratch image",
			content: `FROM scratch
COPY app /app
CMD ["/app"]
`,
			wantPkgs: []struct {
				name     string
				version  string
				purlType string
			}{
				// scratch should be skipped
			},
		},
		{
			name:     "empty file",
			content:  "",
			wantPkgs: nil,
		},
	}

	ext := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &filesystem.ScanInput{
				Path:   "Dockerfile",
				Reader: strings.NewReader(tt.content),
			}

			inv, err := ext.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if len(inv.Packages) != len(tt.wantPkgs) {
				t.Errorf("Extract() got %d packages, want %d", len(inv.Packages), len(tt.wantPkgs))
				for i, pkg := range inv.Packages {
					t.Logf("  package[%d]: %s@%s (type: %s)", i, pkg.Name, pkg.Version, pkg.PURLType)
				}
				return
			}

			for i, want := range tt.wantPkgs {
				got := inv.Packages[i]
				if got.Name != want.name {
					t.Errorf("package[%d].Name = %q, want %q", i, got.Name, want.name)
				}
				if got.Version != want.version {
					t.Errorf("package[%d].Version = %q, want %q", i, got.Version, want.version)
				}
				if got.PURLType != want.purlType {
					t.Errorf("package[%d].PURLType = %q, want %q", i, got.PURLType, want.purlType)
				}
			}
		})
	}
}

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		ref        string
		wantName   string
		wantVer    string
		wantDigest bool
	}{
		{"alpine:3.19", "alpine", "3.19", false},
		{"alpine", "alpine", "latest", false},
		{"docker.io/library/alpine:3.19", "docker.io/library/alpine", "3.19", false},
		{"gcr.io/project/image:v1.0.0", "gcr.io/project/image", "v1.0.0", false},
		{"localhost:5000/myimage:tag", "localhost:5000/myimage", "tag", false},
		{"alpine@sha256:abc123", "alpine", "sha256:abc123", true},
		{"gcr.io/project/image@sha256:def456", "gcr.io/project/image", "sha256:def456", true},
		{"", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			name, ver, hasDigest := splitImageRef(tt.ref)
			if name != tt.wantName {
				t.Errorf("splitImageRef(%q) name = %q, want %q", tt.ref, name, tt.wantName)
			}
			if ver != tt.wantVer {
				t.Errorf("splitImageRef(%q) version = %q, want %q", tt.ref, ver, tt.wantVer)
			}
			if hasDigest != tt.wantDigest {
				t.Errorf("splitImageRef(%q) hasDigest = %v, want %v", tt.ref, hasDigest, tt.wantDigest)
			}
		})
	}
}
