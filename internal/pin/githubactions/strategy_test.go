package githubactions

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/pin"
)

func TestStrategy_DiscoverWorkflows(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: ./local-action
      - uses: docker://alpine:3.19`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)
	if !slices.Contains(names, "actions/checkout") {
		t.Error("missing actions/checkout")
	}
	if !slices.Contains(names, "actions/setup-go") {
		t.Error("missing actions/setup-go")
	}
	for _, r := range refs {
		if strings.HasPrefix(r.Name, ".") || strings.Contains(r.Name, "docker") {
			t.Errorf("unexpected ref discovered: %s", r.Name)
		}
	}
}

func TestStrategy_DiscoverCompositeActions(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4`,
		"action.yml": `
name: My Action
description: A composite action
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - uses: actions/cache@v3`,
		".github/actions/custom/action.yml": `
name: Custom Action
runs:
  using: composite
  steps:
    - uses: actions/upload-artifact@v4`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)
	for _, want := range []string{"actions/checkout", "actions/setup-node", "actions/cache", "actions/upload-artifact"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing %s, got %v", want, names)
		}
	}
}

func TestStrategy_DiscoverNoWorkflows(t *testing.T) {
	fsys := testMapFS(map[string]string{})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs, got %d", len(refs))
	}
}

func TestStrategy_DiscoverSkipsVendor(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"vendor/some-dep/action.yml": `
name: Vendored
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from vendor, got %d", len(refs))
	}
}

func TestStrategy_DiscoverSkipsNodeActions(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"action.yml": `
name: My Node Action
description: A node action
inputs:
  token:
    required: true
runs:
  using: node20
  main: index.js`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from node action, got %d: %v", len(refs), refNames(refs))
	}
}

func TestStrategy_DiscoverDockerAction(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"action.yml": `
name: Docker Action
runs:
  using: docker
  image: Dockerfile`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from docker action, got %d", len(refs))
	}
}

func TestStrategy_DiscoverMalformedYAML(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/bad.yml": `this is not: valid: yaml: [`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from malformed YAML, got %d", len(refs))
	}
}

func TestStrategy_DiscoverViaLocalRef(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./my-action`,
		"my-action/action.yml": `
name: My Action
runs:
  using: composite
  steps:
    - uses: actions/cache@v3`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range refs {
		if r.Name == "actions/cache" && r.Version == "v3" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected actions/cache@v3 to be discovered via local ref, got refs: %v", refNames(refs))
	}
}

func TestStrategy_DiscoverSubpathAction(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) == 0 {
		t.Fatal("expected at least 1 ref for github/codeql-action")
	}
	for _, r := range refs {
		if r.Name != "github/codeql-action" {
			t.Errorf("expected name github/codeql-action, got %s", r.Name)
		}
	}
}

func TestStrategy_DiscoverReusableWorkflow(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  build:
    uses: octo-org/reusable/.github/workflows/build.yml@v2
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)
	if !slices.Contains(names, "actions/checkout") {
		t.Errorf("expected actions/checkout, got %v", names)
	}
	foundReusable := false
	for _, r := range refs {
		if strings.Contains(r.Name, "octo-org") || strings.Contains(r.Name, "reusable") {
			foundReusable = true
		}
	}
	if !foundReusable {
		t.Errorf("expected reusable workflow ref to be discovered, got %v", names)
	}
}

func TestStrategy_DiscoverBranchRefs(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: picatz/deputy/actions/setup@main
      - uses: some-org/tool@dev-branch`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	foundBranch := false
	for _, r := range refs {
		if r.Version == "main" || r.Version == "dev-branch" {
			foundBranch = true
		}
	}
	if !foundBranch {
		t.Errorf("expected branch refs (main/dev-branch) to be discovered")
	}
}

func TestStrategy_DiscoverAlreadyPinnedActions(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-go@v5`,
	})

	s := &Strategy{}
	refs, err := s.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) < 2 {
		t.Fatalf("expected at least 2 refs, got %d", len(refs))
	}

	foundPinned := false
	for _, r := range refs {
		if r.Name == "actions/checkout" && r.IsSHAPinned() {
			foundPinned = true
		}
	}
	if !foundPinned {
		t.Error("expected already-pinned actions/checkout to be discovered with SHA version")
	}
}

func TestStrategy_IsPinned(t *testing.T) {
	s := &Strategy{}
	tests := []struct {
		version string
		want    bool
	}{
		{"11bd71901bbe5b1630ceea73d27597364c9af683", true},
		{"v4", false},
		{"v4.2.2", false},
		{"main", false},
		{"${{ matrix.version }}", false},
	}
	for _, tc := range tests {
		ref := pin.Ref{Version: tc.version}
		if got := s.IsPinned(ref); got != tc.want {
			t.Errorf("IsPinned(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestStrategy_ShouldSkip(t *testing.T) {
	s := &Strategy{}
	tests := []struct {
		version    string
		wantSkip   bool
		wantReason string
	}{
		{"v4", false, ""},
		{"main", false, ""},
		{"11bd71901bbe5b1630ceea73d27597364c9af683", false, ""},
		{"${{ matrix.version }}", true, "expression ref"},
		{"${{ inputs.ref }}", true, "expression ref"},
	}
	for _, tc := range tests {
		ref := pin.Ref{Version: tc.version}
		skip, reason := s.ShouldSkip(ref)
		if skip != tc.wantSkip {
			t.Errorf("ShouldSkip(%q) skip = %v, want %v", tc.version, skip, tc.wantSkip)
		}
		if reason != tc.wantReason {
			t.Errorf("ShouldSkip(%q) reason = %q, want %q", tc.version, reason, tc.wantReason)
		}
	}
}

func TestStrategy_ResolveUpdate(t *testing.T) {
	const (
		oldSHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
		newSHA = "aabbccdd11223344556677889900aabbccddeeff"
	)

	s := &Strategy{
		resolver: testResolver([]refEntry{
			{name: "refs/tags/v4", sha: newSHA},
			{name: "refs/tags/v4.2", sha: oldSHA},
			{name: "refs/tags/v4.2.1", sha: oldSHA},
			{name: "refs/tags/v4.2.2", sha: newSHA},
			{name: "refs/heads/main", sha: newSHA},
		}),
	}

	ref := pin.Ref{Name: "actions/checkout", Version: oldSHA}
	pinnedValue, newTag, currentTag, err := s.ResolveUpdate(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != newSHA {
		t.Errorf("pinnedValue = %q, want %q", pinnedValue, newSHA)
	}
	if currentTag != "v4.2.1" {
		t.Errorf("currentTag = %q, want %q", currentTag, "v4.2.1")
	}
	if newTag != "v4.2.2" {
		t.Errorf("newTag = %q, want %q", newTag, "v4.2.2")
	}
}

func TestStrategy_ResolveUpdateNoChange(t *testing.T) {
	const sha = "11bd71901bbe5b1630ceea73d27597364c9af683"

	s := &Strategy{
		resolver: testResolver([]refEntry{
			{name: "refs/tags/v4", sha: sha},
			{name: "refs/tags/v4.2.2", sha: sha},
			{name: "refs/heads/main", sha: sha},
		}),
	}

	ref := pin.Ref{Name: "actions/checkout", Version: sha}
	pinnedValue, _, _, err := s.ResolveUpdate(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if pinnedValue != sha {
		t.Errorf("expected no change (same SHA), got %q", pinnedValue)
	}
}

// testResolver creates a Resolver with a mock listRefs that returns static refs.
func testResolver(refs []refEntry) *Resolver {
	r := NewResolver()
	r.listRefsFunc = func(_ context.Context, _ string) ([]refEntry, error) {
		return refs, nil
	}
	return r
}

