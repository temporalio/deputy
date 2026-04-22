package pin

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGitHubActionsStrategy_DiscoverWorkflows(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	// Should find the 2 remote actions, but not local or docker
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

func TestGitHubActionsStrategy_DiscoverCompositeActions(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)

	if !slices.Contains(names, "actions/checkout") {
		t.Errorf("missing actions/checkout from workflow, got %v", names)
	}
	if !slices.Contains(names, "actions/setup-node") {
		t.Errorf("missing actions/setup-node from root action.yml, got %v", names)
	}
	if !slices.Contains(names, "actions/cache") {
		t.Errorf("missing actions/cache from root action.yml, got %v", names)
	}
	if !slices.Contains(names, "actions/upload-artifact") {
		t.Errorf("missing actions/upload-artifact from .github/actions/, got %v", names)
	}
}

func TestGitHubActionsStrategy_DiscoverNoWorkflows(t *testing.T) {
	fsys := testMapFS(map[string]string{})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs, got %d", len(refs))
	}
}

func TestGitHubActionsStrategy_DiscoverSkipsVendor(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"vendor/some-dep/action.yml": `
name: Vendored
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from vendor, got %d", len(refs))
	}
}

func TestGitHubActionsStrategy_DiscoverSkipsNodeActions(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from node action, got %d: %v", len(refs), refNames(refs))
	}
}

func TestGitHubActionsStrategy_DiscoverDockerAction(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"action.yml": `
name: Docker Action
runs:
  using: docker
  image: Dockerfile`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from docker action, got %d", len(refs))
	}
}

func TestGitHubActionsStrategy_DiscoverMalformedYAML(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/bad.yml": `this is not: valid: yaml: [`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no refs from malformed YAML, got %d", len(refs))
	}
}

func TestGitHubActionsStrategy_DiscoverViaLocalRef(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
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

func TestGitHubActionsStrategy_DiscoverSubpathAction(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
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

func TestGitHubActionsStrategy_DiscoverSkipsJobContainer(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
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
        image: postgres:15-alpine
    steps:
      - uses: actions/checkout@v4`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range refs {
		name := r.DisplayName()
		if strings.Contains(name, "node") || strings.Contains(name, "redis") || strings.Contains(name, "postgres") {
			t.Errorf("container/service image should not be discovered as a GHA ref: %s", name)
		}
	}
	if !slices.Contains(refNames(refs), "actions/checkout") {
		t.Error("expected actions/checkout to be discovered")
	}
}

func TestGitHubActionsStrategy_DiscoverSkipsJobContainerShortForm(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container: node:18
    steps:
      - uses: actions/checkout@v4`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range refs {
		if strings.Contains(r.DisplayName(), "node") {
			t.Errorf("short-form container image should not be discovered: %s", r.DisplayName())
		}
	}
	if !slices.Contains(refNames(refs), "actions/checkout") {
		t.Error("expected actions/checkout to be discovered")
	}
}

func TestGitHubActionsStrategy_DiscoverSkipsDockerUses(t *testing.T) {
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
      - uses: docker://ghcr.io/owner/image:latest`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range refs {
		if strings.HasPrefix(r.Name, "docker") || strings.Contains(r.Name, "alpine") || strings.Contains(r.Name, "ghcr") {
			t.Errorf("docker:// uses should not appear in discovered refs: %s", r.Name)
		}
	}
	if !slices.Contains(refNames(refs), "actions/checkout") {
		t.Error("expected actions/checkout to be discovered")
	}
}

func TestGitHubActionsStrategy_DiscoverCompositeSkipsDockerUses(t *testing.T) {
	fsys := testMapFS(map[string]string{
		"action.yml": `
name: Mixed Action
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - uses: docker://alpine:3.19
    - uses: ./local-step`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)
	if !slices.Contains(names, "actions/setup-node") {
		t.Error("expected actions/setup-node from composite action")
	}
	for _, r := range refs {
		if strings.Contains(r.Name, "alpine") || strings.Contains(r.Name, "docker") {
			t.Errorf("docker:// in composite action should be filtered: %s", r.Name)
		}
	}
}

func TestGitHubActionsStrategy_IsPinned(t *testing.T) {
	strategy := &GitHubActionsStrategy{}

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
		ref := Ref{Version: tc.version}
		if got := strategy.IsPinned(ref); got != tc.want {
			t.Errorf("IsPinned(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestGitHubActionsStrategy_ShouldSkip(t *testing.T) {
	strategy := &GitHubActionsStrategy{}

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
		ref := Ref{Version: tc.version}
		skip, reason := strategy.ShouldSkip(ref)
		if skip != tc.wantSkip {
			t.Errorf("ShouldSkip(%q) skip = %v, want %v", tc.version, skip, tc.wantSkip)
		}
		if reason != tc.wantReason {
			t.Errorf("ShouldSkip(%q) reason = %q, want %q", tc.version, reason, tc.wantReason)
		}
	}
}

func TestGitHubActionsStrategy_DiscoverReusableWorkflow(t *testing.T) {
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
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

func TestGitHubActionsStrategy_ResolveUpdate(t *testing.T) {
	const (
		oldSHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
		newSHA = "aabbccdd11223344556677889900aabbccddeeff"
	)

	strategy := &GitHubActionsStrategy{
		resolver: testResolver([]refEntry{
			{name: "refs/tags/v4", sha: newSHA},
			{name: "refs/tags/v4.2", sha: oldSHA},
			{name: "refs/tags/v4.2.1", sha: oldSHA},
			{name: "refs/tags/v4.2.2", sha: newSHA},
			{name: "refs/heads/main", sha: newSHA},
		}),
	}

	ref := Ref{Name: "actions/checkout", Version: oldSHA}

	pinnedValue, newTag, currentTag, err := strategy.ResolveUpdate(context.Background(), ref)
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

func TestGitHubActionsStrategy_ResolveUpdateNoChange(t *testing.T) {
	const sha = "11bd71901bbe5b1630ceea73d27597364c9af683"

	strategy := &GitHubActionsStrategy{
		resolver: testResolver([]refEntry{
			{name: "refs/tags/v4", sha: sha},
			{name: "refs/tags/v4.2.2", sha: sha},
			{name: "refs/heads/main", sha: sha},
		}),
	}

	ref := Ref{Name: "actions/checkout", Version: sha}
	pinnedValue, _, _, err := strategy.ResolveUpdate(context.Background(), ref)
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

func TestGitHubActionsStrategy_DiscoverBranchRefs(t *testing.T) {
	// Branch refs like @main, @dev-branch should be discovered and pinnable.
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)
	if !slices.Contains(names, "actions/checkout") {
		t.Errorf("missing actions/checkout, got %v", names)
	}
	// Branch refs should be discovered as pinnable.
	foundBranch := false
	for _, r := range refs {
		if r.Version == "main" || r.Version == "dev-branch" {
			foundBranch = true
		}
	}
	if !foundBranch {
		t.Errorf("expected branch refs (main/dev-branch) to be discovered, got refs: %v", refs)
	}
}

func TestGitHubActionsStrategy_DiscoverAlreadyPinnedActions(t *testing.T) {
	// Actions already pinned to SHAs should still be discovered (for verify/update).
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

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) < 2 {
		t.Fatalf("expected at least 2 refs, got %d", len(refs))
	}

	// The SHA-pinned action should be discovered with the SHA as version.
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

func TestGitHubActionsStrategy_DiscoverMixedWorkflowPatterns(t *testing.T) {
	// A realistic workflow with many different uses patterns.
	fsys := testMapFS(map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  build:
    uses: octo-org/reusable/.github/workflows/build.yml@v2
  test:
    runs-on: ubuntu-latest
    container:
      image: node:18
    services:
      redis:
        image: redis:7
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.4.0
      - uses: picatz/deputy/actions/scan@main
      - uses: docker://alpine:3.19
      - uses: ./local-action
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3`,
		"local-action/action.yml": `
name: Local
runs:
  using: composite
  steps:
    - uses: actions/cache@v3`,
	})

	strategy := &GitHubActionsStrategy{}
	refs, err := strategy.Discover(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	names := refNames(refs)

	// Remote actions with tags should be discovered.
	if !slices.Contains(names, "actions/checkout") {
		t.Errorf("missing actions/checkout, got %v", names)
	}

	// Already-pinned actions should be discovered.
	foundPinnedSetupGo := false
	for _, r := range refs {
		if r.Name == "actions/setup-go" && r.IsSHAPinned() {
			foundPinnedSetupGo = true
		}
	}
	if !foundPinnedSetupGo {
		t.Error("expected pinned actions/setup-go to be discovered")
	}

	// Branch refs should be discovered.
	foundMain := false
	for _, r := range refs {
		if r.Version == "main" {
			foundMain = true
		}
	}
	if !foundMain {
		t.Error("expected @main ref to be discovered")
	}

	// Subpath actions should be discovered.
	foundCodeQL := false
	for _, r := range refs {
		if r.Name == "github/codeql-action" {
			foundCodeQL = true
		}
	}
	if !foundCodeQL {
		t.Error("expected github/codeql-action subpath refs to be discovered")
	}

	// Reusable workflow should be discovered.
	foundReusable := false
	for _, r := range refs {
		if strings.Contains(r.Name, "octo-org") {
			foundReusable = true
		}
	}
	if !foundReusable {
		t.Error("expected reusable workflow ref to be discovered")
	}

	// Local action's deps should be discovered via recursive resolution.
	if !slices.Contains(names, "actions/cache") {
		t.Errorf("expected actions/cache from local composite action, got %v", names)
	}

	// Docker, local, and container/service images should NOT be in refs.
	for _, r := range refs {
		dn := r.DisplayName()
		if strings.Contains(dn, "docker") || strings.Contains(dn, "alpine") ||
			strings.Contains(dn, "node") || strings.Contains(dn, "redis") {
			t.Errorf("unexpected non-action ref discovered: %s@%s", dn, r.Version)
		}
	}
}

// writeTestFile creates a real file for writer tests (which need real filesystem).
func writeTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
