package pin

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestContainerStrategy_IsPinned(t *testing.T) {
	s := NewContainerStrategy()
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
			ref := Ref{Version: tc.version}
			if got := s.IsPinned(ref); got != tc.want {
				t.Errorf("IsPinned(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestContainerStrategy_ShouldSkip(t *testing.T) {
	s := NewContainerStrategy()
	tests := []struct {
		name    string
		version string
		skip    bool
	}{
		{"alpine", "3.19", false},
		{"alpine", "", true},                  // untagged
		{"scratch", "anything", true},         // scratch
		{"image", "${{ matrix.tag }}", true},  // expression
		{"image", "${TAG}", true},             // shell variable
	}
	for _, tc := range tests {
		t.Run(tc.name+":"+tc.version, func(t *testing.T) {
			ref := Ref{Name: tc.name, Version: tc.version}
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

func TestContainerStrategy_DiscoverDockerfile(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": `FROM alpine:3.19
FROM golang:1.23 AS builder
COPY . .
FROM scratch
COPY --from=builder /app /app
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	// Should find alpine:3.19 and golang:1.23, skip scratch.
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

func TestContainerStrategy_DiscoverDockerfileWithPlatform(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": `FROM --platform=linux/amd64 node:22-slim AS runtime
RUN echo hello
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
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

func TestContainerStrategy_DiscoverDockerfileAlreadyPinned(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": `FROM alpine:3.19@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
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

func TestContainerStrategy_DiscoverDockerfileVariant(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"docker/Dockerfile.prod": `FROM nginx:1.25-alpine
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Name != "nginx" || refs[0].Version != "1.25-alpine" {
		t.Errorf("expected nginx:1.25-alpine, got %s:%s", refs[0].Name, refs[0].Version)
	}
}

func TestContainerStrategy_DiscoverWorkflowDockerUses(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
      - uses: docker://ghcr.io/owner/tool:v2
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	// Should find alpine:3.19 and ghcr.io/owner/tool:v2 from docker:// uses.
	// Should NOT find actions/checkout (that's a GHA ref, not a container).
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

func TestContainerStrategy_DiscoverWorkflowContainer(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:18-alpine
    services:
      redis:
        image: redis:7
      postgres:
        image: postgres:16-alpine
    steps:
      - uses: actions/checkout@v4
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d: %v", len(refs), refSummary(refs))
	}

	names := map[string]string{}
	for _, r := range refs {
		names[r.Name] = r.Version
	}
	if names["node"] != "18-alpine" {
		t.Errorf("expected node:18-alpine, got %v", names)
	}
	if names["redis"] != "7" {
		t.Errorf("expected redis:7")
	}
	if names["postgres"] != "16-alpine" {
		t.Errorf("expected postgres:16-alpine")
	}
}

func TestContainerStrategy_DiscoverWorkflowContainerShortForm(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		".github/workflows/ci.yml": `name: CI
on: push
jobs:
  test:
    container: node:18
    steps:
      - uses: actions/checkout@v4
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
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

func TestContainerStrategy_DiscoverSkipsNonDockerfiles(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"main.go":    "package main\nfunc main() {}\n",
		"README.md":  "# Project\n",
		"Makefile":   "build:\n\tgo build .\n",
		".dockerignore": "node_modules\n",
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs from non-Dockerfiles, got %d", len(refs))
	}
}

func TestContainerStrategy_DiscoverMixed(t *testing.T) {
	fsys := testMapFSExact(map[string]string{
		"Dockerfile": `FROM golang:1.23 AS builder
FROM alpine:3.19
`,
		".github/workflows/ci.yml": `name: CI
on: push
jobs:
  test:
    container: postgres:16
    steps:
      - uses: docker://redis:7
`,
	})

	s := NewContainerStrategy()
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 4 {
		t.Fatalf("expected 4 refs (2 Dockerfile + 2 workflow), got %d: %v", len(refs), refSummary(refs))
	}
}

// --- Rewrite tests ---

func TestRewriteContainerRefs_Dockerfile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		updates  []Update
		expected string
	}{
		{
			name:  "basic FROM",
			input: "FROM alpine:3.19\nRUN echo hello\n",
			updates: []Update{
				{Name: "alpine", PinnedValue: "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c", VersionTag: "3.19"},
			},
			expected: "FROM alpine:3.19@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c\nRUN echo hello\n",
		},
		{
			name: "multi-stage",
			input: `FROM golang:1.23 AS builder
COPY . .
RUN go build -o /app .
FROM alpine:3.19
COPY --from=builder /app /app
`,
			updates: []Update{
				{Name: "golang", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "1.23"},
				{Name: "alpine", PinnedValue: "sha256:2222222222222222222222222222222222222222222222222222222222222222", VersionTag: "3.19"},
			},
			expected: `FROM golang:1.23@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS builder
COPY . .
RUN go build -o /app .
FROM alpine:3.19@sha256:2222222222222222222222222222222222222222222222222222222222222222
COPY --from=builder /app /app
`,
		},
		{
			name:  "replace existing digest",
			input: "FROM alpine:3.19@sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
			updates: []Update{
				{Name: "alpine", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "3.19"},
			},
			expected: "FROM alpine:3.19@sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
		},
		{
			name:  "registry-qualified image",
			input: "FROM ghcr.io/owner/image:v1\n",
			updates: []Update{
				{Name: "ghcr.io/owner/image", PinnedValue: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", VersionTag: "v1"},
			},
			expected: "FROM ghcr.io/owner/image:v1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n",
		},
		{
			name:  "with platform flag",
			input: "FROM --platform=linux/amd64 node:22-slim\n",
			updates: []Update{
				{Name: "node", PinnedValue: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", VersionTag: "22-slim"},
			},
			expected: "FROM --platform=linux/amd64 node:22-slim@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n",
		},
		{
			name:     "no match does not modify",
			input:    "FROM scratch\n",
			updates:  []Update{{Name: "alpine", PinnedValue: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", VersionTag: "3.19"}},
			expected: "FROM scratch\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writerTestRoot(t, "Dockerfile", tc.input)
			err := rewriteContainerRefs(root, "Dockerfile", tc.updates)
			if err != nil {
				t.Fatal(err)
			}
			got, err := fs.ReadFile(root.FS(), "Dockerfile")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.expected {
				t.Errorf("mismatch:\ngot:\n%s\nwant:\n%s", string(got), tc.expected)
			}
		})
	}
}

func TestRewriteContainerRefs_Workflow(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    container: postgres:16
    services:
      redis:
        image: redis:7
    steps:
      - uses: docker://alpine:3.19
`
	expected := `name: CI
on: push
jobs:
  test:
    container: postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111
    services:
      redis:
        image: redis:7@sha256:2222222222222222222222222222222222222222222222222222222222222222
    steps:
      - uses: docker://alpine:3.19@sha256:3333333333333333333333333333333333333333333333333333333333333333
`
	root := writerTestRoot(t, ".github/workflows/ci.yml", input)
	err := rewriteContainerRefs(root, ".github/workflows/ci.yml", []Update{
		{Name: "postgres", PinnedValue: "sha256:1111111111111111111111111111111111111111111111111111111111111111", VersionTag: "16"},
		{Name: "redis", PinnedValue: "sha256:2222222222222222222222222222222222222222222222222222222222222222", VersionTag: "7"},
		{Name: "alpine", PinnedValue: "sha256:3333333333333333333333333333333333333333333333333333333333333333", VersionTag: "3.19"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := fs.ReadFile(root.FS(), ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != expected {
		t.Errorf("mismatch:\ngot:\n%s\nwant:\n%s", string(got), expected)
	}
}

func TestRewriteContainerRefs_InvalidDigest(t *testing.T) {
	root := writerTestRoot(t, "Dockerfile", "FROM alpine:3.19\n")
	err := rewriteContainerRefs(root, "Dockerfile", []Update{
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

func TestContainerStrategy_Resolve(t *testing.T) {
	const testDigest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := &ContainerStrategy{
		resolveDigestFunc: func(_ context.Context, imageRef string) (string, error) {
			if imageRef == "alpine:3.19" {
				return testDigest, nil
			}
			return "", fmt.Errorf("unknown image: %s", imageRef)
		},
	}

	pinnedValue, versionTag, err := s.Resolve(context.Background(), Ref{
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

func TestContainerStrategy_ResolveUpdate_Changed(t *testing.T) {
	const (
		oldDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		newDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)

	s := &ContainerStrategy{
		resolveDigestFunc: func(_ context.Context, imageRef string) (string, error) {
			if imageRef == "alpine:3.19" {
				return newDigest, nil
			}
			return "", fmt.Errorf("unknown image: %s", imageRef)
		},
	}

	pinnedValue, newTag, curTag, err := s.ResolveUpdate(context.Background(), Ref{
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

func TestContainerStrategy_ResolveUpdate_NoChange(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := &ContainerStrategy{
		resolveDigestFunc: func(_ context.Context, _ string) (string, error) {
			return digest, nil
		},
	}

	ref := Ref{Name: "alpine", Version: "3.19@" + digest}
	pinnedValue, _, _, err := s.ResolveUpdate(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != ref.Version {
		t.Errorf("expected no change, got pinnedValue=%q", pinnedValue)
	}
}

// --- Orchestration integration tests ---

func TestContainerPin_EndToEnd(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := &ContainerStrategy{
		resolveDigestFunc: func(_ context.Context, _ string) (string, error) {
			return digest, nil
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{
		DryRun:           true,
		SkipVerification: true,
	}, s)
	if err != nil {
		t.Fatal(err)
	}

	// Empty temp dir — no Dockerfiles or workflows to find.
	if report.Stats.Total != 0 {
		t.Errorf("expected 0 total in empty dir, got %d", report.Stats.Total)
	}
}

func TestContainerVerify_ReportsNotAvailable(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := NewContainerStrategy()

	// Verify returns (nil, nil) for containers — the orchestrator should
	// NOT mark this as "verified" but as "already-pinned" with a reason.
	ref := Ref{
		Ecosystem: EcosystemContainerImage,
		Name:      "alpine",
		Version:   "3.19@" + digest,
	}

	v, err := s.Verify(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Error("expected nil Verification for containers")
	}
}

func TestContainerStrategy_ResolveUpdate_DigestOnly(t *testing.T) {
	const digest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

	s := &ContainerStrategy{
		resolveDigestFunc: func(_ context.Context, _ string) (string, error) {
			t.Fatal("should not resolve for digest-only ref")
			return "", nil
		},
	}

	// Digest-only ref (no tag) — can't check for updates.
	ref := Ref{Name: "alpine", Version: digest}
	pinnedValue, _, _, err := s.ResolveUpdate(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != ref.Version {
		t.Errorf("expected no change for digest-only, got %q", pinnedValue)
	}
}

