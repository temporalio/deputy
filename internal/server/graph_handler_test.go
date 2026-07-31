package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/dependency/graph"
)

func TestGraphBuilderOptions(t *testing.T) {
	t.Run("defaults to local-only resolution", func(t *testing.T) {
		got := graphBuilderOptions(nil)
		if got.UseProxy {
			t.Fatal("UseProxy = true, want false")
		}
		if got.UseGit {
			t.Fatal("UseGit = true, want false")
		}
		if got.UseDepsDevTransitives {
			t.Fatal("UseDepsDevTransitives = true, want false")
		}
		if got.PrivatePatterns != nil {
			t.Fatalf("PrivatePatterns = %v, want nil", got.PrivatePatterns)
		}
	})

	t.Run("use proxy enables registry-backed transitive resolution", func(t *testing.T) {
		opts := &graphv1.GraphOptions{UseProxy: true}
		got := graphBuilderOptions(opts)
		if !got.UseProxy {
			t.Fatal("UseProxy = false, want true")
		}
		if !got.UseDepsDevTransitives {
			t.Fatal("UseDepsDevTransitives = false, want true")
		}
	})

	t.Run("use git and private patterns do not imply public registry resolution", func(t *testing.T) {
		opts := &graphv1.GraphOptions{
			UseGit:          true,
			PrivatePatterns: []string{"corp.example/*"},
		}
		got := graphBuilderOptions(opts)
		if !got.UseGit {
			t.Fatal("UseGit = false, want true")
		}
		if got.UseDepsDevTransitives {
			t.Fatal("UseDepsDevTransitives = true, want false")
		}
		if !slices.Equal(got.PrivatePatterns, []string{"corp.example/*"}) {
			t.Fatalf("PrivatePatterns = %v, want [corp.example/*]", got.PrivatePatterns)
		}
		opts.PrivatePatterns[0] = "mutated.example/*"
		if !slices.Equal(got.PrivatePatterns, []string{"corp.example/*"}) {
			t.Fatalf("PrivatePatterns changed after input mutation: %v", got.PrivatePatterns)
		}
	})
}

func TestGraphHandlerBuildGraphGoModuleIsNotEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	h := NewGraphHandler(WithGraphLocalMode())
	resp, err := h.BuildGraph(context.Background(), connect.NewRequest(&graphv1.BuildGraphRequest{
		Target: tmpDir,
		Options: &graphv1.GraphOptions{
			Ecosystems: []string{"go"},
			UseProxy:   false,
			UseGit:     false,
		},
	}))
	if err != nil {
		t.Fatalf("BuildGraph() error: %v", err)
	}

	if got := resp.Msg.GetStats().GetTotalNodes(); got == 0 {
		t.Fatal("BuildGraph() returned an empty graph for a Go module with requirements")
	}
	if len(resp.Msg.GetRoots()) == 0 {
		t.Fatal("BuildGraph() returned no roots for a Go module with requirements")
	}
	if !graphResponseHasNode(resp.Msg, "pkg:golang/github.com/pkg/errors@0.9.1") {
		t.Fatalf("BuildGraph() missing github.com/pkg/errors node; nodes = %v", graphResponseNodePURLs(resp.Msg))
	}
}

func TestGraphHandlerBuildGraphHonorsExplicitGitRef(t *testing.T) {
	tmpDir := t.TempDir()
	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("git init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	firstGoMod := `module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1
`
	writeGraphTestFile(t, tmpDir, "go.mod", firstGoMod)
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("git add first go.mod: %v", err)
	}
	firstHash, err := wt.Commit("first", &git.CommitOptions{Author: testGitSignature()})
	if err != nil {
		t.Fatalf("git commit first: %v", err)
	}

	secondGoMod := `module example.com/app

go 1.21

require github.com/google/uuid v1.6.0
`
	writeGraphTestFile(t, tmpDir, "go.mod", secondGoMod)
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("git add second go.mod: %v", err)
	}
	if _, err := wt.Commit("second", &git.CommitOptions{Author: testGitSignature()}); err != nil {
		t.Fatalf("git commit second: %v", err)
	}

	h := NewGraphHandler(WithGraphLocalMode())
	tests := []struct {
		name       string
		targetHint targetv1.TargetKind
	}{
		{name: "autodetected local repository"},
		{name: "explicit git target hint", targetHint: targetv1.TargetKind_TARGET_KIND_GIT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.BuildGraph(t.Context(), connect.NewRequest(&graphv1.BuildGraphRequest{
				Target: tmpDir,
				Options: &graphv1.GraphOptions{
					Ecosystems: []string{"go"},
					Ref:        firstHash.String(),
					TargetHint: tt.targetHint,
				},
			}))
			if err != nil {
				t.Fatalf("BuildGraph() error: %v", err)
			}

			if !graphResponseHasNode(resp.Msg, "pkg:golang/github.com/pkg/errors@0.9.1") {
				t.Fatalf("BuildGraph() at first ref missing github.com/pkg/errors; nodes = %v", graphResponseNodePURLs(resp.Msg))
			}
			if graphResponseHasNode(resp.Msg, "pkg:golang/github.com/google/uuid@1.6.0") {
				t.Fatalf("BuildGraph() ignored ref and scanned working tree; nodes = %v", graphResponseNodePURLs(resp.Msg))
			}
			target := resp.Msg.GetTarget()
			if target.GetRef() != firstHash.String() {
				t.Fatalf("target.ref = %q, want %q", target.GetRef(), firstHash.String())
			}
			if target.GetCommitHash() != firstHash.String() {
				t.Fatalf("target.commit_hash = %q, want %q", target.GetCommitHash(), firstHash.String())
			}
			// Edges must resolve from the ref's snapshot workspace: a nil
			// workspace silently downgrades ref builds to a disconnected
			// basic graph with no dependency paths.
			if len(resp.Msg.GetEdges()) == 0 {
				t.Fatalf("BuildGraph() at ref resolved no edges; ref snapshot workspace missing")
			}
		})
	}
}

func TestGraphHandlerBuildGraphExtendedMarksLocalPathGoModules(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	h := NewGraphHandler(WithGraphLocalMode())
	resp, err := h.BuildGraph(context.Background(), connect.NewRequest(&graphv1.BuildGraphRequest{
		Target: tmpDir,
		Options: &graphv1.GraphOptions{
			Ecosystems: []string{"go"},
			Extended:   true,
		},
	}))
	if err != nil {
		t.Fatalf("BuildGraph() error: %v", err)
	}

	stats := resp.Msg.GetStats().GetImportStatusCounts()
	if stats == nil {
		t.Fatal("extended BuildGraph() did not populate import status counts")
	}
	if stats.GetRequired() == 0 {
		t.Fatalf("required import status count = 0, want at least one: %+v", stats)
	}

	node := graphResponseNode(resp.Msg, "pkg:golang/github.com/pkg/errors@0.9.1")
	if node == nil {
		t.Fatalf("BuildGraph() missing github.com/pkg/errors node; nodes = %v", graphResponseNodePURLs(resp.Msg))
	}
	if got := node.GetImportStatus(); got != graphv1.ImportStatus_IMPORT_STATUS_REQUIRED {
		t.Fatalf("github.com/pkg/errors import status = %v, want REQUIRED", got)
	}
}

func TestGraphHandlerWhyDependencyReturnsMatchedNodeAndNoPathMessage(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1 // indirect
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	h := NewGraphHandler(WithGraphLocalMode())
	resp, err := h.WhyDependency(context.Background(), connect.NewRequest(&graphv1.WhyDependencyRequest{
		Target:     tmpDir,
		Dependency: "pkg:golang/github.com/pkg/errors@0.9.1",
		Options: &graphv1.GraphOptions{
			Ecosystems: []string{"go"},
		},
	}))
	if err != nil {
		t.Fatalf("WhyDependency() error: %v", err)
	}
	if !resp.Msg.GetFound() {
		t.Fatal("WhyDependency() did not find github.com/pkg/errors")
	}
	if len(resp.Msg.GetPaths()) != 0 {
		t.Fatalf("WhyDependency() paths = %d, want 0", len(resp.Msg.GetPaths()))
	}
	node := resp.Msg.GetDependencyNode()
	if node == nil {
		t.Fatal("WhyDependency() missing dependency_node for pathless match")
	}
	if got, want := node.GetPurl(), "pkg:golang/github.com/pkg/errors@0.9.1"; got != want {
		t.Fatalf("dependency_node.purl = %q, want %q", got, want)
	}
	if !strings.Contains(resp.Msg.GetMessage(), "disconnected from dependency roots") {
		t.Fatalf("message = %q, want disconnected context", resp.Msg.GetMessage())
	}
}

func TestFindMatchingNodesMatchesPURLIdentity(t *testing.T) {
	g := graph.New()
	const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	g.AddNode(&graph.Node{
		Purl:    dockerPURL,
		Name:    "github.com/docker/docker",
		Version: "28.5.2+incompatible",
	})

	matches := findMatchingNodes(g, "pkg:golang/github.com/docker/docker@28.5.2+incompatible")
	if len(matches) != 1 {
		t.Fatalf("findMatchingNodes() matched %d nodes, want 1", len(matches))
	}
	if matches[0].GetPurl() != dockerPURL {
		t.Fatalf("findMatchingNodes() matched %q, want %q", matches[0].GetPurl(), dockerPURL)
	}
}

func writeGraphTestFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testGitSignature() *object.Signature {
	return &object.Signature{
		Name:  "Deputy Test",
		Email: "deputy-test@example.com",
		When:  time.Now(),
	}
}

func graphResponseHasNode(resp *graphv1.BuildGraphResponse, purl string) bool {
	return graphResponseNode(resp, purl) != nil
}

func graphResponseNode(resp *graphv1.BuildGraphResponse, purl string) *graphv1.Node {
	for _, node := range resp.GetNodes() {
		if node.GetPurl() == purl {
			return node
		}
	}
	return nil
}

func graphResponseNodePURLs(resp *graphv1.BuildGraphResponse) []string {
	nodes := resp.GetNodes()
	purls := make([]string, 0, len(nodes))
	for _, node := range nodes {
		purls = append(purls, node.GetPurl())
	}
	return purls
}
