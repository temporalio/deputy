package container

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/temporalio/deputy/internal/pin"
)

// --- Test helpers ---

type mapFSAdapter struct {
	fstest.MapFS
}

func (m *mapFSAdapter) Open(name string) (fs.File, error) {
	return m.MapFS.Open(name)
}

var _ scalibrfs.FS = (*mapFSAdapter)(nil)

func testMapFSExact(files map[string]string) scalibrfs.FS {
	m := fstest.MapFS{}
	for path, content := range files {
		m[path] = &fstest.MapFile{Data: []byte(content)}
	}
	return &mapFSAdapter{m}
}

func writerTestRoot(t *testing.T, relPath, content string) *os.Root {
	t.Helper()
	tmp := t.TempDir()
	full := filepath.Join(tmp, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func refSummary(refs []pin.Ref) string {
	var parts []string
	for _, r := range refs {
		parts = append(parts, r.Name+":"+r.Version)
	}
	return strings.Join(parts, ", ")
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading testdata/%s: %v", name, err)
	}
	return string(data)
}

// --- Unit tests ---

func TestStrategy_IsPinned(t *testing.T) {
	s := NewStrategy()
	tests := []struct {
		version string
		want    bool
	}{
		{"3.19", false},
		{"latest", false},
		{"v1.0.0", false},
		{"sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c", true},
		{"3.19@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c", true},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			ref := pin.Ref{Version: tc.version}
			if got := s.IsPinned(ref); got != tc.want {
				t.Errorf("IsPinned(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestStrategy_ShouldSkip(t *testing.T) {
	s := NewStrategy()
	tests := []struct {
		name    string
		version string
		skip    bool
	}{
		{"alpine", "3.19", false},
		{"alpine", "", true},                 // untagged
		{"scratch", "anything", true},        // scratch
		{"image", "${{ matrix.tag }}", true}, // expression
		{"image", "${TAG}", true},            // shell variable
	}
	for _, tc := range tests {
		t.Run(tc.name+":"+tc.version, func(t *testing.T) {
			ref := pin.Ref{Name: tc.name, Version: tc.version}
			skip, _ := s.ShouldSkip(ref)
			if skip != tc.skip {
				t.Errorf("ShouldSkip(%q, %q) = %v, want %v", tc.name, tc.version, skip, tc.skip)
			}
		})
	}
}

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		raw     string
		name    string
		version string
	}{
		{"alpine:3.19", "alpine", "3.19"},
		{"alpine", "alpine", ""},
		{"alpine:latest", "alpine", "latest"},
		{"ghcr.io/owner/image:v1", "ghcr.io/owner/image", "v1"},
		{"localhost:5000/myapp:v1", "localhost:5000/myapp", "v1"},
		{"alpine@sha256:abc123", "alpine", "sha256:abc123"},
		{"alpine:3.19@sha256:abc123", "alpine", "3.19@sha256:abc123"},
		{"gcr.io/project/image:tag@sha256:abc123", "gcr.io/project/image", "tag@sha256:abc123"},
		{"", "", ""},
		{"scratch", "scratch", ""},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			name, version := splitImageRef(tc.raw)
			if name != tc.name || version != tc.version {
				t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)",
					tc.raw, name, version, tc.name, tc.version)
			}
		})
	}
}

func TestSplitTagDigest(t *testing.T) {
	tests := []struct {
		version    string
		wantTag    string
		wantDigest string
	}{
		{"3.19@sha256:abc", "3.19", "sha256:abc"},
		{"sha256:abc", "", "sha256:abc"},
		{"3.19", "3.19", ""},
		{"latest", "latest", ""},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			tag, digest := splitTagDigest(tc.version)
			if tag != tc.wantTag || digest != tc.wantDigest {
				t.Errorf("splitTagDigest(%q) = (%q, %q), want (%q, %q)",
					tc.version, tag, digest, tc.wantTag, tc.wantDigest)
			}
		})
	}
}

func TestIsDockerfile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"Dockerfile.dev", true},
		{"Dockerfile.prod", true},
		{"app.dockerfile", true},
		{"main.go", false},
		{"ci.yml", false},
		{"README.md", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDockerfile(tc.name); got != tc.want {
				t.Errorf("isDockerfile(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// --- Discovery tests ---

func TestStrategy_DiscoverDockerfile(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": "FROM alpine:3.19\nFROM golang:1.23 AS builder\nCOPY . .\nFROM scratch\nCOPY --from=builder /app /app\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refSummary(refs))
	}

	names := map[string]string{}
	for _, r := range refs {
		names[r.Name] = r.Version
	}
	if names["alpine"] != "3.19" {
		t.Errorf("expected alpine:3.19, got %v", names)
	}
	if names["golang"] != "1.23" {
		t.Errorf("expected golang:1.23, got %v", names)
	}
}

func TestStrategy_DiscoverDockerfileWithPlatform(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": "FROM --platform=linux/amd64 node:22-slim AS runtime\nRUN echo hello\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Name != "node" || refs[0].Version != "22-slim" {
		t.Errorf("expected node:22-slim, got %s:%s", refs[0].Name, refs[0].Version)
	}
}

func TestStrategy_DiscoverDockerfileAlreadyPinned(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": "FROM alpine:3.19@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if !s.IsPinned(refs[0]) {
		t.Error("expected ref to be pinned")
	}
}

func TestStrategy_DiscoverWorkflowDockerUses(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: docker://alpine:3.19\n      - uses: docker://ghcr.io/owner/tool:v2\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refSummary(refs))
	}

	names := map[string]string{}
	for _, r := range refs {
		names[r.Name] = r.Version
	}
	if names["alpine"] != "3.19" {
		t.Errorf("expected alpine:3.19")
	}
	if names["ghcr.io/owner/tool"] != "v2" {
		t.Errorf("expected ghcr.io/owner/tool:v2")
	}
}

func TestStrategy_DiscoverWorkflowContainer(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    container:\n      image: node:18-alpine\n    services:\n      redis:\n        image: redis:7\n      postgres:\n        image: postgres:16-alpine\n    steps:\n      - uses: actions/checkout@v4\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d: %v", len(refs), refSummary(refs))
	}
}

func TestStrategy_DiscoverWorkflowContainerShortForm(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    container: node:18\n    steps:\n      - uses: actions/checkout@v4\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d: %v", len(refs), refSummary(refs))
	}
	if refs[0].Name != "node" || refs[0].Version != "18" {
		t.Errorf("expected node:18, got %s:%s", refs[0].Name, refs[0].Version)
	}
}

func TestStrategy_DiscoverSkipsNonDockerfiles(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"main.go":       "package main\nfunc main() {}\n",
		"README.md":     "# Project\n",
		".dockerignore": "node_modules\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs from non-Dockerfiles, got %d", len(refs))
	}
}

func TestStrategy_DiscoverMixed(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile":               "FROM golang:1.23 AS builder\nFROM alpine:3.19\n",
		".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    container: postgres:16\n    steps:\n      - uses: docker://redis:7\n",
	})

	s := NewStrategy()
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 4 {
		t.Fatalf("expected 4 refs (2 Dockerfile + 2 workflow), got %d: %v", len(refs), refSummary(refs))
	}
}

// --- Rewrite golden tests ---

func TestRewriteContainerRefs_Golden(t *testing.T) {
	tests := []struct {
		name    string
		input   string // testdata filename (input)
		golden  string // testdata filename (expected output)
		relPath string // file path to use for rewrite
		updates []pin.Update
	}{
		{
			name:    "basic FROM",
			input:   "dockerfile_basic.input",
			golden:  "dockerfile_basic.golden",
			relPath: "Dockerfile",
			updates: []pin.Update{
				{Name: "alpine", PinnedValue: "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c", VersionTag: "3.19"},
			},
		},
		{
			name:    "multi-stage",
			input:   "dockerfile_multistage.input",
			golden:  "dockerfile_multistage.golden",
			relPath: "Dockerfile",
			updates: []pin.Update{
				{Name: "golang", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "1.23"},
				{Name: "alpine", PinnedValue: "sha256:2222222222222222222222222222222222222222222222222222222222222222", VersionTag: "3.19"},
			},
		},
		{
			name:    "with platform flag",
			input:   "dockerfile_platform.input",
			golden:  "dockerfile_platform.golden",
			relPath: "Dockerfile",
			updates: []pin.Update{
				{Name: "node", PinnedValue: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", VersionTag: "22-slim"},
			},
		},
		{
			name:    "replace existing digest",
			input:   "dockerfile_replace_digest.input",
			golden:  "dockerfile_replace_digest.golden",
			relPath: "Dockerfile",
			updates: []pin.Update{
				{Name: "alpine", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "3.19"},
			},
		},
		{
			name:    "workflow containers",
			input:   "workflow_containers.input.yml",
			golden:  "workflow_containers.golden.yml",
			relPath: ".github/workflows/ci.yml",
			updates: []pin.Update{
				{Name: "postgres", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "16"},
				{Name: "redis", PinnedValue: "sha256:2222222222222222222222222222222222222222222222222222222222222222", VersionTag: "7"},
				{Name: "alpine", PinnedValue: "sha256:3333333333333333333333333333333333333333333333333333333333333333", VersionTag: "3.19"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := readTestdata(t, tc.input)
			want := readTestdata(t, tc.golden)

			root := writerTestRoot(t, tc.relPath, input)

			if err := rewriteContainerRefs(root, tc.relPath, tc.updates); err != nil {
				t.Fatal(err)
			}

			got, err := fs.ReadFile(root.FS(), tc.relPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("output mismatch (-want +got):\n--- want\n%s\n--- got\n%s", want, string(got))
			}
		})
	}
}

func TestRewriteContainerRefs_InvalidDigest(t *testing.T) {
	root := writerTestRoot(t, "Dockerfile", "FROM alpine:3.19\n")
	err := rewriteContainerRefs(root, "Dockerfile", []pin.Update{
		{Name: "alpine", PinnedValue: "not-a-digest", VersionTag: "3.19"},
	})
	if err == nil {
		t.Fatal("expected error for invalid digest")
	}
	if !strings.Contains(err.Error(), "not a valid digest") {
		t.Errorf("error should mention invalid digest, got: %v", err)
	}
}

// --- Resolve tests (with mock) ---

func TestStrategy_Resolve(t *testing.T) {
	const testDigest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := NewStrategyWithResolver(func(_ context.Context, imageRef string) (string, error) {
		if imageRef == "alpine:3.19" {
			return testDigest, nil
		}
		return "", fmt.Errorf("unknown image: %s", imageRef)
	})

	pinnedValue, versionTag, err := s.Resolve(t.Context(), pin.Ref{
		Name:    "alpine",
		Version: "3.19",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != testDigest {
		t.Errorf("pinnedValue = %q, want %q", pinnedValue, testDigest)
	}
	if versionTag != "3.19" {
		t.Errorf("versionTag = %q, want %q", versionTag, "3.19")
	}
}

func TestStrategy_ResolveUpdate_Changed(t *testing.T) {
	const (
		oldDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		newDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)

	s := NewStrategyWithResolver(func(_ context.Context, imageRef string) (string, error) {
		if imageRef == "alpine:3.19" {
			return newDigest, nil
		}
		return "", fmt.Errorf("unknown image: %s", imageRef)
	})

	pinnedValue, newTag, curTag, err := s.ResolveUpdate(t.Context(), pin.Ref{
		Name:    "alpine",
		Version: "3.19@" + oldDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != newDigest {
		t.Errorf("pinnedValue = %q, want %q", pinnedValue, newDigest)
	}
	if newTag != "3.19" || curTag != "3.19" {
		t.Errorf("tags = (%q, %q), want (3.19, 3.19)", newTag, curTag)
	}
}

func TestStrategy_ResolveUpdate_NoChange(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := NewStrategyWithResolver(func(_ context.Context, _ string) (string, error) {
		return digest, nil
	})

	ref := pin.Ref{Name: "alpine", Version: "3.19@" + digest}
	pinnedValue, _, _, err := s.ResolveUpdate(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != ref.Version {
		t.Errorf("expected no change, got pinnedValue=%q", pinnedValue)
	}
}

func TestStrategy_ResolveUpdate_DigestOnly(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := NewStrategyWithResolver(func(_ context.Context, _ string) (string, error) {
		t.Fatal("should not resolve for digest-only ref")
		return "", nil
	})

	ref := pin.Ref{Name: "alpine", Version: digest}
	pinnedValue, _, _, err := s.ResolveUpdate(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != ref.Version {
		t.Errorf("expected no change for digest-only, got %q", pinnedValue)
	}
}

func TestStrategy_Verify_ReturnsNil(t *testing.T) {
	s := NewStrategy()
	v, err := s.Verify(t.Context(), pin.Ref{})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Error("expected nil Verification for containers")
	}
}
